#include <cstdlib>
#include <string_view>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <functional>
#include <future>
#include <sys/wait.h>
#include <cstdarg>
#include <sys/stat.h>

//#undef NDEBUG // uncomment this line to enable asserts in use below
#include <cassert>
#include <optional>

#ifdef NDEBUG
void __assert (const char *__assertion, const char *__file, int __line) __THROW {}
#endif

// extern and forward function declarations
extern int sniff();
extern int tunnel();
static std::optional<std::string> find_program_path(const std::string_view prog, const std::string_view path_var_name);

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

  const std::string_view arg{argv[1]};
  if (arg == "-sniff") {
    return sniff();
  }

  auto ip_path_optn = find_program_path("ip", "PATH");
  if (ip_path_optn->empty()) return EXIT_FAILURE;
  const auto ip_path = ip_path_optn.value();

  const pid_t pid = fork();
  if (pid == -1) {
    fprintf(stderr, "pid(%d): fork() failed: %s\n", getpid(), strerror(errno));
    return EXIT_FAILURE;
  } else if (pid == 0) {
    // child process
    const char * const ip_prg = strdup(ip_path.data());
    const char * const netns = strdup(arg.data());
    const char * const child_prg = strdup(progpath());
    const std::array<const char*, 7> child_argv =
        { ip_prg, "netns", "exec", netns, child_prg, "-sniff", nullptr };
    int rc = execv(ip_prg, const_cast<char**>(child_argv.data()));
    if (rc == -1) {
      fprintf(stderr, "pid(%d): failed to exec '%s': %s", getpid(), ip_prg, strerror(errno));
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
          fprintf(stderr, "failed waiting for forked child process (pid:%d): %s\n", getpid(), strerror(errno));
          return EXIT_FAILURE;
        }
        if (WIFSIGNALED(status) || WIFSTOPPED(status)) {
          fprintf(stderr, "interrupted waiting for forked child process (pid:%d)\n", child_pid);
          return EXIT_FAILURE;
        }
      } while (!WIFEXITED(status) && !WIFSIGNALED(status));

      fprintf(stdout, "**** fork/exec terminating per child process (pid:%d); exit status: %d ****\n", child_pid, status);

      return status == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    };

    // Initiate two async task:
    //  1) wait on the child process (the invocation with -sniff option)
    //  2) tunnel packets to outside world (as piped to and from the child process)
    std::function<int()> wait_on_sniffer_task = wait_on_sniffer;
    std::function<int()> tunnel_task = tunnel;
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

  fprintf(stderr, "could not locate program '%s' via %s environment variable", prog.data(), path_var_name.data());
  return std::nullopt;
}