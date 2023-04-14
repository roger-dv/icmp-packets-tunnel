/* main.cpp

Copyright 2023 Roger D. Voss

Created by github user roger-dv on 03/07/2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
#include <cstdlib>
#include <string_view>
#include <cstdio>
#include <cerrno>
#include <functional>
#include <future>
#include <sys/wait.h>
#include <sys/stat.h>
#include <optional>
#include <sys/capability.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/mount.h>

//#undef NDEBUG // uncomment this line to enable asserts in use below
#include <cassert>

#ifdef NDEBUG
void __assert (const char *__assertion, const char *__file, int __line) __THROW {}
#endif

// extern and forward function declarations
extern int sniff(int pipe_out, sockaddr_un addr, socklen_t addr_len);
extern int reply(int pipe_in);
extern int tunnel(int pipe_in, const std::string_view dst_net_addr);
extern int relay(int pipe_out, sockaddr_un addr, socklen_t addr_len);
static std::optional<std::function<void()>> modify_cap(cap_value_t capability, cap_flag_value_t setting);
static std::string make_uds_socket_name(const std::string_view prg_name, const std::string_view fifo_pipe_basename);

// RAII-related declarations for managing file/pipe descriptors (to clean these up if exception thrown)
struct fd_wrapper_t {
  int fd;
  fd_wrapper_t() = delete;
  explicit fd_wrapper_t(int fd) : fd{fd} {}
};
using fd_wrapper_cleanup_t = void(*)(fd_wrapper_t *);
using fd_wrapper_sp_t = std::unique_ptr<fd_wrapper_t, fd_wrapper_cleanup_t>;
static std::optional<fd_wrapper_sp_t> bind_uds_socket_name(
    const std::string_view uds_socket_name, sockaddr_un &addr, socklen_t &addr_len, const bool skip_bind = false);

// static data definitions
static std::string_view sniffer_uds = "Sniffer_UDS";
static std::string_view replier_uds = "Replier_UDS";
static int s_parent_thread_pid = 0;
static std::string_view s_prog_path;
static std::string_view s_prog_name;
// getters for above static variables
inline int get_parent_pid() { return s_parent_thread_pid; }
__attribute__((noinline)) const char* prog_path() { return s_prog_path.data(); }
__attribute__((noinline)) const std::string_view prog_name() { return s_prog_name; }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "LocalValueEscapesScope"
#pragma ide diagnostic ignored "UnreachableCode"
#pragma ide diagnostic ignored "UnusedValue"
#pragma ide diagnostic ignored "UnusedParameter"
static void one_time_init(int argc, const char *argv[]) {
  s_parent_thread_pid = getpid();

  const char *malloced_tmpstr = nullptr;

  {
    malloced_tmpstr = strdup(argv[0]); // heap allocates the string storage
    if (malloced_tmpstr == nullptr) {
      __assert("strdup() could not duplicate program full path name on startup", __FILE__, __LINE__);
      _exit(EXIT_FAILURE); // will exit here if __assert() defined to no-op function
    }
    s_prog_path = malloced_tmpstr; // static string_view variable takes ownership for program runtime duration
  }

  {
    malloced_tmpstr = [](const char* const path) -> const char* {
      auto const dup_path = strdupa(path); // stack allocates the string storage (will go away on return)
      return strdup(basename(dup_path));   // heap allocates the string storage
    }(prog_path());
    if (malloced_tmpstr == nullptr) {
      __assert("strdup() could not duplicate program base name on startup", __FILE__, __LINE__);
      _exit(EXIT_FAILURE); // will exit here if __assert() defined to no-op function
    }
    s_prog_name = malloced_tmpstr; // static string_view variable takes ownership for program runtime duration
  }

  static const auto uds_socket_name_sniff = make_uds_socket_name(prog_name(), sniffer_uds);
  static const auto uds_socket_name_reply = make_uds_socket_name(prog_name(), replier_uds);

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
  auto const prn_usage = [prg = prog_name()] {
    printf("Usage: %s net_ns_name -ping destination_ip\n", prg.data());
  };

  if (argc < 4) {
    prn_usage();
    return argc == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  {
    // The CAP_NET_RAW Linux capability will permit invoking this call
    // with the IPPROTO_RAW protocol:
    //
    // int dst_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    //
    auto rslt = modify_cap(CAP_NET_RAW, CAP_SET);
    if (rslt.has_value()) {
      rslt.value()(); // report error condition to stderr
      fputs("ERROR: failed setting Linux capability CAP_NET_RAW; can't create socket of IPPROTO_RAW protocol\n", stderr);
      return EXIT_FAILURE;
    }
  }

  // argument #1 is the required command-line specified network namespace
  const std::string_view net_ns_arg{argv[1]};

  std::string_view dst_net_addr{""};
  {
    // obtain the IPv4 network address specified via -ping command-line option
    // and verify that it's a valid, reachable destination IP address
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

  // Unix Domain Socket names as used for parent process vis-à-vis child process communications
  const auto uds_socket_name_sniff = make_uds_socket_name(prog_name(), sniffer_uds);
  const auto uds_socket_name_reply = make_uds_socket_name(prog_name(), replier_uds);

  const pid_t pid = fork();
  if (pid == -1) {
    fprintf(stderr, "ERROR: pid(%d): fork() failed: %s\n", getpid(), strerror(errno));
    return EXIT_FAILURE;
  } else if (pid == 0) {
    /***** child process *****/

    // before can proceed to set the command-line specified network namespace
    // for this child process, must have CAP_SYS_ADMIN capability
    auto rslt = modify_cap(CAP_SYS_ADMIN, CAP_SET);
    if (rslt.has_value()) {
      rslt.value()(); // report error condition to stderr
      fprintf(stderr, "ERROR: failed setting Linux capability CAP_SYS_ADMIN - can't access network namespace: \"%s\"\n",
              net_ns_arg.data());
      return EXIT_FAILURE;
    }

    // construct the network namespace full path
    std::string ns_path{"/var/run/netns/"};
    ns_path += net_ns_arg;

    // open a file descriptor on the network namespace; leave
    // open for duration of using the network namespace context
    const int net_namespace_fd = open(ns_path.c_str(), O_RDONLY);
    if (net_namespace_fd == -1) {
      const auto ec = errno;
      fprintf(stderr, "ERROR: open(\"%s\", O_RDONLY): per forked child process (pid:%d): ec=%d; %s\n",
              ns_path.c_str(), getpid(), ec, strerror(ec));
      return EXIT_FAILURE;
    }
    auto const cleanup_fd = [](const int *p) {
      if (p != nullptr) {
        close(*p);
      }
    };
    std::unique_ptr<const int, decltype(cleanup_fd)> net_ns_fd_sp{ &net_namespace_fd, cleanup_fd };

    // remove the parent-inherited network namespace context on this child process
    if (unshare(CLONE_NEWNET) == -1) {
      const auto ec = errno;
      fprintf(stderr, "ERROR: unshare(..): per forked child process (pid:%d): ec=%d; %s\n", getpid(), ec, strerror(ec));
      return EXIT_FAILURE;
    }
    // switch this child process to the command-line specified network namespace
    if (setns(net_namespace_fd, CLONE_NEWNET) == -1) {
      const auto ec = errno;
      fprintf(stderr, "ERROR: setns(..): per forked child process (pid:%d): ec=%d; %s\n", getpid(), ec, strerror(ec));
      return EXIT_FAILURE;
    }
    // make the command-line specified network namespace the default for this child process via mount()
    if (mount("/proc/self/ns/net", ns_path.c_str(), "none", MS_BIND , nullptr) == -1) {
      const auto ec = errno;
      fprintf(stderr, "ERROR: mount(..) of \"%s\": per forked child process (pid:%d): ec=%d; %s\n",
              ns_path.c_str(), getpid(), ec, strerror(ec));
      return EXIT_FAILURE;
    }

    // the sniff_task and the reply_task will now proceed to operate
    // in the context of the command-line specified network namespace
    // (they will use Unix Domain Sockets to communicate with the
    //  original tunl parent process)
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

    bool have_valid_shared_state = false;
    for(int i = 5; i > 0; i--) {
      if (have_valid_shared_state = fut1.valid() && fut2.valid(); have_valid_shared_state) break;
      sleep(1);
    }
    if (!have_valid_shared_state) {
      fprintf(stderr, "ERROR: sniff_task and reply_task of child process (pid=%d) have unexpectedly not started", getpid());
      return EXIT_FAILURE;
    }

    // wait on the task futures
    const auto rc1 = fut1.get();
    const auto rc2 = fut2.get();

    return rc1 == EXIT_SUCCESS ? rc2 : rc1;
  } else {
    /***** parent process *****/

    // a lambda that implements waiting on the forked child process
    std::function<int()> wait_on_sniffer_task = [child_pid=pid] {
      // now wait on the child process pid (which will be executing the sniff_task and reply_task)
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

      fprintf(stdout, "**** termination of forked child process (pid:%d); exit status: %d ****\n", child_pid, status);

      if (status != 0) _exit(EXIT_FAILURE);
      return EXIT_SUCCESS;
    };

    // the tunnel_task and relay_task will proceed to operate
    // in the context of the default host network namespace
    // (they will use Unix Domain Sockets to communicate with
    //  the forked child process)
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

    // Initiate three async task:
    //  1) wait on the child process (which operates in the context of the command-line specified network namespace)
    //  2) tunnel packets to outside world (as piped from the child process)
    //  3) tunnel outside world packets back to the child process
    std::function<int()> tunnel_task =
        [pipe_in = socket_fd_sniff_sp.release()->fd, dst = dst_net_addr.data()] { return tunnel(pipe_in, dst); };
    std::function<int()> relay_task =
        [pipe_out = socket_fd_reply_sp.release()->fd, addr = reply_addr, addr_len = reply_addr_len] {
          return relay(pipe_out, addr, addr_len);
        };
    std::future<int> fut1 = std::async(std::launch::async, std::move(wait_on_sniffer_task));
    std::future<int> fut2 = std::async(std::launch::async, std::move(tunnel_task));
    std::future<int> fut3 = std::async(std::launch::async, std::move(relay_task));

    bool have_valid_shared_state = false;
    for(int i = 5; i > 0; i--) {
      if (have_valid_shared_state = fut1.valid() && fut2.valid() && fut3.valid(); have_valid_shared_state) break;
      sleep(1);
    }
    if (!have_valid_shared_state) {
      fprintf(stderr, "ERROR: worker task of parent process (pid=%d) have unexpectedly not started", getpid());
      return EXIT_FAILURE;
    }

    // wait on the task futures
    const auto rc1 = fut1.get();
    const auto rc2 = fut2.get();
    const auto rc3 = fut3.get();
    return rc1 == EXIT_SUCCESS ? (rc2 == EXIT_SUCCESS ? rc3 : rc2) : rc1;
  }
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "ConstantParameter"
/**
 * Utility function for setting or clearing a Linux capability on the process of the caller.
 *
 * @param capability the Linux capability to be set or cleared
 * @param setting enum that specifies whether to set or clear the capability
 * @return empty optional on success; an error reporting lambda on failure
 */
static std::optional<std::function<void()>> modify_cap(cap_value_t capability, cap_flag_value_t setting) {
  std::string_view fn{__FUNCTION__};
  const std::array<cap_value_t, 1> cap_list{ capability };
  cap_t const caps = cap_get_proc();
  if (caps == nullptr) {
    return [ec=errno, pfn=fn.data()]() {
      fprintf(stderr, "ERROR: %s(..): call to cap_get_proc() failed: ec=%d; %s\n", pfn, ec, strerror(ec));
    };
  }
  auto const clean_up = [](cap_t p) {
    if (p != nullptr) {
      cap_free(p);
    }
  };
  std::unique_ptr<std::remove_pointer<cap_t>::type, decltype(clean_up)> caps_sp{caps, clean_up};

  if (cap_set_flag(caps, CAP_EFFECTIVE, cap_list.size(), cap_list.data(), setting) == -1) {
    return [ec=errno, pfn=fn.data()]() {
      fprintf(stderr, "ERROR: %s(..): call to cap_set_flag(..) failed: ec=%d; %s\n", pfn, ec, strerror(ec));
    };
  }

  if (cap_set_proc(caps) == -1) {
    return [ec=errno, pfn=fn.data()]() {
      fprintf(stderr, "ERROR: %s(..): call to cap_set_proc(..) failed: ec=%d; %s\n", pfn, ec, strerror(ec));
    };
  }

  return std::nullopt;
}
#pragma clang diagnostic pop

//
// Utility function that makes a UDS (Unix Domain) socket name
//
static std::string make_uds_socket_name(const std::string_view prg_name, const std::string_view fifo_pipe_basename) {
  const auto pid = getpid();
  int str_buf_size = 256;
  char *str_buf = reinterpret_cast<char *>(alloca(str_buf_size));
  do_msg_fmt:
  {
    int n = str_buf_size;
    n = snprintf(str_buf, static_cast<size_t>(n), "%s/%s_%s", "/tmp", prg_name.data(), fifo_pipe_basename.data());
    if (n <= 0) {
      fprintf(stderr, "ERROR: %s() process %d Failed synthesizing FIFO_PIPE name string", __FUNCTION__, pid);
      return "";
    }
    if (n >= str_buf_size) {
      str_buf = reinterpret_cast<char *>(alloca(str_buf_size = ++n));
      goto do_msg_fmt; // try do_msg_fmt again
    }
  }
  return str_buf;
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

  auto const fd_cleanup_with_delete = [](fd_wrapper_t *p) {
    if (p != nullptr && p->fd != -1) {
      close(p->fd);
      p->fd = -1;
    }
    delete p;
  };
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