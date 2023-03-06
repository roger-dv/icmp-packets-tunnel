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

//#undef NDEBUG // uncomment this line to enable asserts in use below
#include <cassert>

#ifdef NDEBUG
void __assert (const char *__assertion, const char *__file, int __line) __THROW {}
#endif

// extern and forward function declarations
extern int sniff(int pipe_out);
extern int reply(int pipe_in);
extern int tunnel(int pipe_in, int pipe_out);
static std::string format2str(const char *const fmt, ...);
static std::optional<std::string> find_program_path(const std::string_view prog, const std::string_view path_var_name);
static std::string make_fifo_pipe_name(const std::string_view progname, const std::string_view fifo_pipe_basename);

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
static std::optional<fd_wrapper_sp_t> bind_uds_socket_name(const std::string_view uds_socket_name);
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
}
#pragma clang diagnostic pop

int main(const int argc, const char *argv[]) {
  one_time_init(argc, argv);
  auto const prn_usage = [prg=progname()] { printf("Usage: %s [-sniff|netns_name]\n", prg.data()); };

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
    auto socket_fd_sniff_sp_optn = bind_uds_socket_name(uds_socket_name_sniff);
    if (!socket_fd_sniff_sp_optn.has_value()) return EXIT_FAILURE;
    auto socket_fd_reply_sp_optn = bind_uds_socket_name(uds_socket_name_reply);
    if (!socket_fd_reply_sp_optn.has_value()) return EXIT_FAILURE;
    auto socket_fd_sniff_sp = std::move(socket_fd_sniff_sp_optn.value());
    auto socket_fd_reply_sp = std::move(socket_fd_reply_sp_optn.value());

    std::function<int()> sniff_task = [pipe_out=socket_fd_sniff_sp.release()->fd] { return sniff(pipe_out); };
    std::function<int()> reply_task = [pipe_in=socket_fd_reply_sp.release()->fd]  { return reply(pipe_in);  };
    std::future<int> fut1 = std::async(std::launch::async, std::move(sniff_task));
    std::future<int> fut2 = std::async(std::launch::async, std::move(reply_task));

    // wait on the task futures
    const auto rc1 = fut1.get();
    const auto rc2 = fut2.get();

    return rc1 == EXIT_SUCCESS ? rc2 : rc1;
  }

  auto ip_path_optn = find_program_path("ip", "PATH");
  if (ip_path_optn->empty()) return EXIT_FAILURE;
  const auto ip_path = ip_path_optn.value();

  const auto uds_socket_name_sniff = make_fifo_pipe_name(progpath(), "Sniffer_UDS");
  const auto uds_socket_name_reply = make_fifo_pipe_name(progpath(), "Replier_UDS");

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

    auto socket_fd_sniff_sp_optn = bind_uds_socket_name(uds_socket_name_sniff);
    if (!socket_fd_sniff_sp_optn.has_value()) return EXIT_FAILURE;
    auto socket_fd_reply_sp_optn = bind_uds_socket_name(uds_socket_name_reply);
    if (!socket_fd_reply_sp_optn.has_value()) return EXIT_FAILURE;
    auto socket_fd_sniff_sp = std::move(socket_fd_sniff_sp_optn.value());
    auto socket_fd_reply_sp = std::move(socket_fd_reply_sp_optn.value());

    // Initiate two async task:
    //  1) wait on the child process (the invocation with -sniff option)
    //  2) tunnel packets to outside world (as piped to and from the child process)
    std::function<int()> wait_on_sniffer_task = wait_on_sniffer;
    std::function<int()> tunnel_task =
        [pipe_in=socket_fd_sniff_sp.release()->fd, pipe_out=socket_fd_reply_sp.release()->fd]
        { return tunnel(pipe_in, pipe_out); };
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

static volatile unsigned int seed = static_cast<unsigned>(time(nullptr));

#pragma clang diagnostic push
#pragma ide diagnostic ignored "ConstantParameter"
static int get_rnd_nbr(const unsigned int min_n, const unsigned int max_n) {
  auto this_seed = seed;
  auto rnd_n = rand_r(&this_seed);
  const unsigned int range = 1 + max_n - min_n;
  const unsigned int buckets = RAND_MAX / range;
  const decltype(rnd_n) limit = buckets * range;
  while (rnd_n >= limit) {
    rnd_n = rand_r(&this_seed);
  }
  seed = this_seed;
  return min_n + rnd_n / buckets;
}
#pragma clang diagnostic pop

//
// Utility function that makes a fifo pipe name
//
static std::string make_fifo_pipe_name(const std::string_view progname, const std::string_view fifo_pipe_basename) {
  const auto pid = getpid();
  int strbuf_size = 256;
  char *strbuf = reinterpret_cast<char *>(alloca(strbuf_size));
  do_msg_fmt:
  {
    int n = strbuf_size;
    n = snprintf(strbuf, static_cast<size_t>(n), "%s/%s_%s_%d_%d",
                 "/tmp", progname.data(), fifo_pipe_basename.data(), pid, get_rnd_nbr(1, 99));
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
/*
static void fd_cleanup_no_delete(fd_wrapper_t *p) {
  if (p != nullptr && p->fd != -1) {
    close(p->fd);
    p->fd = -1;
  }
}
*/
static void fd_cleanup_with_delete(fd_wrapper_t *p) {
  if (p != nullptr && p->fd != -1) {
    close(p->fd);
    p->fd = -1;
  }
  delete p;
}

static int create_uds_socket() {
  int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
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
  addr.sun_path[0] = '\0';
  addr_len = sizeof(sockaddr_un) - (sizeof(addr.sun_path) - uds_sock_name.size());
}

static std::optional<fd_wrapper_sp_t> bind_uds_socket_name(const std::string_view uds_socket_name) {
  const int fd = create_uds_socket();
  if (fd < 0) return std::nullopt;
  fd_wrapper_sp_t socket_fd_sp{ new fd_wrapper_t{ fd }, fd_cleanup_with_delete };

  sockaddr_un server_address{};
  socklen_t address_length;
  init_sockaddr(uds_socket_name, server_address, address_length);

  int rc = bind(socket_fd_sp->fd, reinterpret_cast<const sockaddr*>(&server_address), address_length);
  if (rc < 0) {
    const auto ec = errno;
    fprintf(stderr, "ERROR: failed binding UDS socket for i/o: %d: %s", ec, strerror(ec));
    return std::nullopt;
  }

  return std::make_optional<fd_wrapper_sp_t>(std::move(socket_fd_sp));
}