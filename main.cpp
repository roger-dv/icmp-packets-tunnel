#include <cstdlib>
#include <string_view>
#include <cstdio>
#include <cerrno>
#include <functional>
#include <future>
#include <sys/wait.h>
#include <cstdarg>
#include <sys/stat.h>
#include <optional>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

//#undef NDEBUG // uncomment this line to enable asserts in use below
#include <cassert>

#ifdef NDEBUG
void __assert (const char *__assertion, const char *__file, int __line) __THROW {}
#endif

// extern and forward function declarations
extern int sniff(int pipe_out, sockaddr_un addr, socklen_t addr_len);
extern int reply(int pipe_in);
extern int tunnel(int pipe_in, int pipe_out, sockaddr_un addr, socklen_t addr_len, const std::string_view dst_net_addr);
static std::string format2str(const char *const fmt, ...);
static std::optional<std::string> find_program_path(const std::string_view prog, const std::string_view path_var_name);
static std::string make_uds_socket_name(const std::string_view progname, const std::string_view fifo_pipe_basename);

// RAII-related declarations for managing file/pipe descriptors (to clean these up if exception thrown)
struct fd_wrapper_t {
  pid_t const pid;
  int fd;
  std::string const name;
  explicit fd_wrapper_t(int fd) : pid{0}, fd{fd}, name{} {}
  explicit fd_wrapper_t(int fd, const char * const name) : pid{ ::getpid() }, fd{fd}, name{name} {}
};
using fd_wrapper_cleanup_t = void(*)(fd_wrapper_t *);
using fd_wrapper_sp_t = std::unique_ptr<fd_wrapper_t, fd_wrapper_cleanup_t>;
static std::optional<fd_wrapper_sp_t> bind_uds_socket_name(
    const std::string_view uds_socket_name, sockaddr_un &addr, socklen_t &addr_len, const bool skip_bind = false);
//static void fd_cleanup_no_delete(fd_wrapper_t *);
static void fd_cleanup_with_delete(fd_wrapper_t *);

// static data definitions
static int s_parent_thrd_pid = 0;
static std::string_view s_progpath;
static std::string_view s_progname;
// getters for above static variabls
inline int get_parent_pid() { return s_parent_thrd_pid; }
__attribute__((noinline)) const char* progpath() { return s_progpath.data(); }
__attribute__((noinline)) const std::string_view progname() { return s_progname; }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "LocalValueEscapesScope"
#pragma ide diagnostic ignored "UnreachableCode"
static void one_time_init(int argc, const char *argv[]) {
  s_parent_thrd_pid = getpid();

  const char *malloced_tmpstr = nullptr;

  {
    malloced_tmpstr = strdup(argv[0]); // heap allocates the string storage
    if (malloced_tmpstr == nullptr) {
      __assert("strdup() could not duplicate program full path name on startup", __FILE__, __LINE__);
      _exit(EXIT_FAILURE); // will exit here if __assert() defined to no-op function
    }
    s_progpath = malloced_tmpstr; // static string_view variable takes ownership for program runtime duration
  }

  {
    malloced_tmpstr = [](const char* const path) -> const char* {
      auto const dup_path = strdupa(path); // stack allocates the string storage (will go away on return)
      return strdup(basename(dup_path));   // heap allocates the string storage
    }(progpath());
    if (malloced_tmpstr == nullptr) {
      __assert("strdup() could not duplicate program base name on startup", __FILE__, __LINE__);
      _exit(EXIT_FAILURE); // will exit here if __assert() defined to no-op function
    }
    s_progname = malloced_tmpstr; // static string_view variable takes ownership for program runtime duration
  }

  static const auto uds_socket_name_sniff = make_uds_socket_name(progname(), "Sniffer_UDS");
  static const auto uds_socket_name_reply = make_uds_socket_name(progname(), "Replier_UDS");

  auto const sig_handler = [](int sig) {
    if (sig != SIGINT && sig != SIGTERM) return;
    std::array<std::string_view, 2> uds_names = { uds_socket_name_sniff, uds_socket_name_reply };
    for(const auto uds_name : uds_names) {
      int rc = remove(uds_name.data());
      if (rc < 0) {
        const auto ec = errno;
        if (ec != ENOENT) {
          fprintf(stderr, "WARN: %s(..): remove(\"%s\"): failed removing UDS socket file path: %d: %s\n",
                  __FUNCTION__ , uds_name.data(), ec, strerror(ec));
        }
      }
    }
    _exit(EXIT_SUCCESS);
  };

  if (signal(SIGINT, sig_handler) != SIG_ERR && signal(SIGTERM, sig_handler) != SIG_ERR) return;
  __assert("signal() failed to install signal handler", __FILE__, __LINE__);
  _exit(EXIT_FAILURE); // will exit here if __assert() defined to no-op function
}
#pragma clang diagnostic pop

int main(const int argc, const char *argv[]) {
  one_time_init(argc, argv);
  auto const prn_usage = [prg=progname()] {
    printf("Usage: %s [-sniff|netns_name] [-ping] destination_ip]\n", prg.data());
  };

  if (argc < 2) {
    prn_usage();
    return EXIT_FAILURE;
  }

  const std::string_view arg1{argv[1]};
  if (arg1 == "-sniff") {
    std::string uds_socket_name_sniff;
    std::string uds_socket_name_reply;
    for(int i = 2; i < argc; i++) {
      const std::string_view arg{argv[i]};
      if (arg.starts_with("-pipe-sniff=")) {
        auto delimiter = std::find(arg.begin(), arg.end(), '=');
        delimiter++;
        uds_socket_name_sniff = std::string(delimiter, arg.end());
      } else if (arg.starts_with("-pipe-reply=")) {
        auto delimiter = std::find(arg.begin(), arg.end(), '=');
        delimiter++;
        uds_socket_name_reply = std::string(delimiter, arg.end());
      }
    }
    if (uds_socket_name_sniff.empty() || uds_socket_name_reply.empty()) {
      fputs("ERROR: UDS socket names per options -pipe-sniff or -pipe-reply not detected", stderr);
      return EXIT_FAILURE;
    }
    sockaddr_un sniff_addr{};
    socklen_t sniff_addr_len;
    sockaddr_un reply_addr{};
    socklen_t reply_addr_len;
    auto socket_fd_sniff_sp_optn = bind_uds_socket_name(uds_socket_name_sniff, sniff_addr, sniff_addr_len, true);
    if (!socket_fd_sniff_sp_optn.has_value()) return EXIT_FAILURE;
    auto socket_fd_reply_sp_optn = bind_uds_socket_name(uds_socket_name_reply, reply_addr, reply_addr_len);
    if (!socket_fd_reply_sp_optn.has_value()) return EXIT_FAILURE;
    auto socket_fd_sniff_sp = std::move(socket_fd_sniff_sp_optn.value());
    auto socket_fd_reply_sp = std::move(socket_fd_reply_sp_optn.value());

    std::function<int()> sniff_task =
        [pipe_out = socket_fd_sniff_sp.release()->fd, addr = sniff_addr, addr_len = sniff_addr_len] {
          return sniff(pipe_out, addr, addr_len);
        };
    std::function<int()> reply_task = [pipe_in=socket_fd_reply_sp.release()->fd]  { return reply(pipe_in);  };
    std::future<int> fut1 = std::async(std::launch::async, std::move(sniff_task));
    std::future<int> fut2 = std::async(std::launch::async, std::move(reply_task));

    // wait on the task futures
    const auto rc1 = fut1.get();
    const auto rc2 = fut2.get();

    return rc1 == EXIT_SUCCESS ? rc2 : rc1;
  }

  std::string_view dst_net_addr{""};
  {
    for(int i = 2; i < argc; i++) {
      const std::string_view arg{argv[i]};
      if (arg == "-ping") {
        const int j = i + 1;
        if (j >= argc) {
          fputs("ERROR: -ping option missing destination IPv4 address argument\n", stderr);
          return EXIT_FAILURE;
        }
        dst_net_addr = argv[j];
        struct in_addr dst;
        memset(&dst, 0, sizeof dst);
        if (inet_aton(dst_net_addr.data(), &dst) == 0) {
          fprintf(stderr, "ERROR: inet_aton(__cp=\"%s\"): isn't a valid destination IP address\n", dst_net_addr.data());
          return EXIT_FAILURE;
        }
        i = j;
      }
    }
    if (dst_net_addr.empty()) {
      fputs("ERROR: destination IP address not specified", stderr);
      return EXIT_FAILURE;
    }
  }

  auto ip_path_optn = find_program_path("ip", "PATH");
  if (ip_path_optn->empty()) return EXIT_FAILURE;
  const auto ip_path = ip_path_optn.value();

  const auto uds_socket_name_sniff = make_uds_socket_name(progname(), "Sniffer_UDS");
  const auto uds_socket_name_reply = make_uds_socket_name(progname(), "Replier_UDS");

  const pid_t pid = fork();
  if (pid == -1) {
    fprintf(stderr, "ERROR: pid(%d): fork() failed: %s\n", getpid(), strerror(errno));
    return EXIT_FAILURE;
  } else if (pid == 0) {
    // child process
    const char * const ip_prg = strdup(ip_path.data());
    const char * const netns = strdup(arg1.data());
    const char * const child_prg = strdup(progpath());
    const auto pipe_sniff_optn = format2str("-pipe-sniff=%s", uds_socket_name_sniff.c_str());
    const auto pipe_reply_optn = format2str("-pipe-reply=%s", uds_socket_name_reply.c_str());
    const std::array<const char*, 9> child_argv =
      { ip_prg, "netns", "exec", netns, child_prg, "-sniff", pipe_sniff_optn.c_str(), pipe_reply_optn.c_str(), nullptr };

    // exec the program that will run as this child process (classic fork/exec)
    int ec = execv(ip_prg, const_cast<char**>(child_argv.data()));
    if (ec == -1) {
      fprintf(stderr, "ERROR: pid(%d): failed to exec '%s': %s", getpid(), ip_prg, strerror(errno));
      return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
  } else {
    // parent process
    auto const wait_on_sniffer = [child_pid=pid, parent_pid=get_parent_pid()] {
      // now wait on the child process pid (which will call the sniff() function due the -sniff option)
      int status = 0;
      do {
        if (waitpid(child_pid, &status, 0) == -1) {
          fprintf(stderr, "ERROR: failed waiting for forked child process (pid:%d): %s\n", getpid(), strerror(errno));
          return EXIT_FAILURE;
        }
        if (WIFSIGNALED(status) || WIFSTOPPED(status)) {
          fprintf(stderr, "ERROR: interrupted waiting for forked child process (pid:%d)\n", child_pid);
          return EXIT_FAILURE;
        }
      } while (!WIFEXITED(status) && !WIFSIGNALED(status));

      fprintf(stdout, "**** fork/exec terminating per child process (pid:%d); exit status: %d ****\n", child_pid, status);

      return status == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    };

    sockaddr_un sniff_addr{};
    socklen_t sniff_addr_len;
    sockaddr_un reply_addr{};
    socklen_t reply_addr_len;
    auto socket_fd_sniff_sp_optn = bind_uds_socket_name(uds_socket_name_sniff, sniff_addr, sniff_addr_len);
    if (!socket_fd_sniff_sp_optn.has_value()) return EXIT_FAILURE;
    auto socket_fd_reply_sp_optn = bind_uds_socket_name(uds_socket_name_reply, reply_addr, reply_addr_len, true);
    if (!socket_fd_reply_sp_optn.has_value()) return EXIT_FAILURE;
    auto socket_fd_sniff_sp = std::move(socket_fd_sniff_sp_optn.value());
    auto socket_fd_reply_sp = std::move(socket_fd_reply_sp_optn.value());

    // Initiate two async task:
    //  1) wait on the child process (the invocation with -sniff option)
    //  2) tunnel packets to outside world (as piped to and from the child process)
    std::function<int()> wait_on_sniffer_task = wait_on_sniffer;
    std::function<int()> tunnel_task =
        [pipe_in = socket_fd_sniff_sp.release()->fd, pipe_out = socket_fd_reply_sp.release()->fd,
            addr = reply_addr, addr_len = reply_addr_len, dst=dst_net_addr.data()] {
          return tunnel(pipe_in, pipe_out, addr, addr_len, dst);
        };
    std::future<int> fut1 = std::async(std::launch::async, std::move(wait_on_sniffer_task));
    std::future<int> fut2 = std::async(std::launch::async, std::move(tunnel_task));
    // wait on the task futures
    const auto rc1 = fut1.get();
    const auto rc2 = fut2.get();
    return rc1 == EXIT_SUCCESS ? rc2 : rc1;
  }
}

static std::string vformat2str(const char *const fmt, va_list ap) {
  int strbuf_size = 256;
  int n = strbuf_size;
  char *strbuf = (char*) alloca(strbuf_size);
  va_list parm_copy;
  va_copy(parm_copy, ap);
  {
    n = vsnprintf(strbuf, (size_t) n, fmt, ap);
    assert(n > 0);
    if (n >= strbuf_size) {
      strbuf = (char*) alloca(strbuf_size = ++n);
      n = vsnprintf(strbuf, (size_t) n, fmt, parm_copy);
      assert(n > 0 && n < strbuf_size);
    }
  }
  va_end(parm_copy);
  return strbuf; // returns std::string obj via Return Value Optimization
}

static std::string format2str(const char *const fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  auto rslt = vformat2str(fmt, ap);
  va_end(ap);
  return rslt; // returns std::string obj via Return Value Optimization
}

static std::string get_env_var(const std::string_view name) {
  char * const val = getenv(name.data());
  return val != nullptr ? std::string(val) : std::string();
}

static std::optional<std::string> find_program_path(const std::string_view prog, const std::string_view path_var_name) {
  const auto path_env_var = get_env_var(path_var_name);

  if (path_env_var.empty()) {
    fprintf(stderr, "ERROR: there is no %s environment variable defined", path_var_name.data());
    return std::nullopt;
  }

  const char * const path_env_var_dup = strdupa(path_env_var.c_str());

  static const char * const delim = ":";
  char *save = nullptr;
  const char * path = strtok_r(const_cast<char*>(path_env_var_dup), delim, &save);

  while(path != nullptr) {
//    fprintf(stderr, "'%s'\n", path);
    const auto len = strlen(path);
    const char end_char = path[len - 1];
    const char * const fmt = end_char == '/' ? "%s%s" : "%s/%s";
    const auto full_path = format2str(fmt, path, prog.data());
//    fprintf(stderr, "'%s'\n", full_path.c_str());
    // check to see if program file path exist
    struct stat statbuf{0};
    if (stat(full_path.c_str(), &statbuf) != -1 && ((statbuf.st_mode & S_IFMT) == S_IFREG ||
                                                    (statbuf.st_mode & S_IFMT) == S_IFLNK))
    {
      return full_path;
    }
    path = strtok_r(nullptr, delim, &save);
  }

  fprintf(stderr, "ERROR: could not locate program '%s' via %s environment variable", prog.data(), path_var_name.data());
  return std::nullopt;
}

//
// Utility function that makes a UDS (Unix Domain) socket name
//
static std::string make_uds_socket_name(const std::string_view progname, const std::string_view fifo_pipe_basename) {
  const auto pid = getpid();
  int strbuf_size = 256;
  char *strbuf = reinterpret_cast<char *>(alloca(strbuf_size));
  do_msg_fmt:
  {
    int n = strbuf_size;
    n = snprintf(strbuf, static_cast<size_t>(n), "%s/%s_%s", "/tmp", progname.data(), fifo_pipe_basename.data());
    if (n <= 0) {
      fprintf(stderr, "ERROR: %s() process %d Failed synthesizing FIFO_PIPE name string", __FUNCTION__, pid);
      return "";
    }
    if (n >= strbuf_size) {
      strbuf = reinterpret_cast<char *>(alloca(strbuf_size = ++n));
      goto do_msg_fmt; // try do_msg_fmt again
    }
  }
  return strbuf;
}

static void fd_cleanup_with_delete(fd_wrapper_t *p) {
  if (p != nullptr && p->fd != -1) {
    close(p->fd);
    p->fd = -1;
  }
  delete p;
}

static int create_uds_socket() {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    const auto ec = errno;
    fprintf(stderr, "ERROR: socket(..): failed create UDS socket: ec=%d; %s\n", ec, strerror(ec));
  }
  return fd;
}

static void init_sockaddr(const std::string_view uds_sock_name, sockaddr_un &addr, socklen_t &addr_len) {
  memset(&addr, 0, sizeof(sockaddr_un));
  addr.sun_family = AF_UNIX;
  auto const path_buf_end = sizeof(addr.sun_path) - 1;
  strncpy(addr.sun_path, uds_sock_name.data(), path_buf_end);
  addr.sun_path[path_buf_end] = '\0';
  addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path) + 1;
}

static std::optional<fd_wrapper_sp_t> bind_uds_socket_name(
    const std::string_view uds_socket_name, sockaddr_un &addr, socklen_t &addr_len, const bool skip_bind)
{
  const std::string_view fn{__FUNCTION__};

  // create the socket
  const int fd = create_uds_socket();
  if (fd < 0) return std::nullopt;
  fd_wrapper_sp_t socket_fd_sp{ new fd_wrapper_t{ fd }, fd_cleanup_with_delete };

  init_sockaddr(uds_socket_name, addr, addr_len);
  fprintf(stderr, "DEBUG: %s(..): UDS socket name: \"%s\"\n", fn.data(), addr.sun_path);

  if (!skip_bind) {
    int rc;
    // restrict permissions
#ifdef __linux__
    rc = fchmod(socket_fd_sp->fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH | S_IXOTH);
    if (rc < 0) {
      const auto ec = errno;
      fprintf(stderr, "ERROR: %s(..): fchmod(__fd=%d,..): failed setting permissions: %d: %s\n",
              fn.data(), socket_fd_sp->fd, ec, strerror(ec));
      return std::nullopt;
    }
#endif

    rc = remove(addr.sun_path);
    if (rc < 0) {
      const auto ec = errno;
      if (ec != ENOENT) {
        fprintf(stderr, "ERROR: %s(..): remove(\"%s\"): failed removing UDS socket file path: %d: %s\n",
                fn.data(), addr.sun_path, ec, strerror(ec));
        return std::nullopt;
      }
    }

    // bind the socket now
    rc = bind(socket_fd_sp->fd, reinterpret_cast<const sockaddr *>(&addr), addr_len);
    if (rc < 0) {
      const auto ec = errno;
      fprintf(stderr, "ERROR: %s(..): bind(__fd=%d,..): failed binding UDS socket for i/o: %d: %s\n",
              fn.data(), socket_fd_sp->fd, ec, strerror(ec));
      return std::nullopt;
    }

    // finally, fix the permissions to one's liking
    rc = chmod(addr.sun_path, 0666);  // <- change 0666 to what your permissions need to be
    if (rc < 0) {
      const auto ec = errno;
      fprintf(stderr, "ERROR: %s(..): chmod(\"%s\",..): failed setting permissions: %d: %s\n",
              fn.data(), addr.sun_path, ec, strerror(ec));
      return std::nullopt;
    }
  }

  return std::make_optional<fd_wrapper_sp_t>(std::move(socket_fd_sp));
}