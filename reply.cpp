#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <array>
#include <unistd.h>
#include <memory>

int reply(int pipe_in) {
  const std::string_view fn{__FUNCTION__};
  fprintf(stderr, "DEBUG: %s(..) invoked\n", fn.data());
  auto const close_fd = [](int *p) {
    if (p != nullptr) {
      close(*p);
    }
  };
  std::unique_ptr<int, decltype(close_fd)> sp_fd_in{&pipe_in, close_fd};

  const std::string_view suffix{"(..): "};
  std::array<char, 2048> buf{};
  for(;;) {
    fd_set read_set;
    memset(&read_set, 0, sizeof read_set);
    FD_SET(pipe_in, &read_set);

    struct timeval timeout = {3, 0}; // wait max 3 seconds for a reply
    int rc = select(pipe_in + 1, &read_set, nullptr, nullptr, &timeout);
    fprintf(stderr, "DEBUG: %s(..): %d = select(..)\n", fn.data(), rc);
    if (rc == 0) {
      continue;
    } else if (rc < 0) {
      const auto ec = errno;
      if (ec == EINTR) break; // signal occurred
      fprintf(stderr, "ERROR: %s(..): select(..): ec=%d; %s\n", fn.data() , ec, strerror(ec));
      return EXIT_FAILURE;
    }

    rc = read(pipe_in, buf.data(), buf.size());
    if (rc < 0) {
      const auto ec = errno;
      fprintf(stderr, "ERROR: %s(..): reading tunnel pipe input failed: %d %s\n", fn.data() , ec, strerror(ec));
      return EXIT_FAILURE;
    }
    if (rc == 0) break; // eof
    if (rc > 0) {
      int n = write(STDOUT_FILENO, fn.data(), fn.size());
      n = write(STDOUT_FILENO, suffix.data(), suffix.size());
      n = write(STDOUT_FILENO, buf.data(), rc);
      if (n != rc) {
        const auto ec = errno;
        fprintf(stderr, "ERROR: %s(..): writing output failed: %d %s\n", fn.data() , ec, strerror(ec));
        return EXIT_FAILURE;
      }
    }
  }

  return EXIT_SUCCESS;
}