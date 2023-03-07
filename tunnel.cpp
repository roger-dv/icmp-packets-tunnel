#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <array>
#include <unistd.h>
#include <memory>
#include <sys/socket.h>
#include <sys/un.h>

int tunnel(int pipe_in, int pipe_out, sockaddr_un addr, socklen_t addr_len) {
  const std::string_view fn{__FUNCTION__};
  printf("DEBUG: %s(..) invoked\n", fn.data());
  auto const close_fd = [](int *p) {
    if (p != nullptr) {
      close(*p);
    }
  };
  std::unique_ptr<int, decltype(close_fd)> sp_fd_in{&pipe_in, close_fd};
  std::unique_ptr<int, decltype(close_fd)> sp_fd_out{&pipe_out, close_fd};

  for(;;) {
    if (connect(pipe_out, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == -1) {
      const auto ec = errno;
      fprintf(stderr, "WARN: %s(..): connect(__fd=%d,addr=\"%s\"..): ec=%d; %s\n",
              fn.data(), pipe_out, addr.sun_path, ec, strerror(ec));
      sleep(3);
      continue;
    }
    break;
  }

  if (listen(pipe_in, 5) == -1) {
    const auto ec = errno;
    fprintf(stderr, "ERROR: %s(..): listen(__fd=%d,..): ec=%d; %s\n", fn.data(), pipe_in, ec, strerror(ec));
    return EXIT_FAILURE;
  }

  int fd = accept(pipe_in, nullptr, nullptr);
  if (fd == -1) {
    const auto ec = errno;
    fprintf(stderr, "WARN: %s(..): accept(__fd=%d,..): ec=%d; %s\n", fn.data(), pipe_in, ec, strerror(ec));
    return EXIT_FAILURE;
  }
  std::unique_ptr<int, decltype(close_fd)> sp_fd{&fd, close_fd};

  std::array<char, 2048> buf{};

  for(;;) {
    fd_set read_set;
    memset(&read_set, 0, sizeof read_set);
    FD_SET(fd, &read_set);

    struct timeval timeout = {3, 0}; // wait max 3 seconds for a reply
    int rc = select(fd + 1, &read_set, nullptr, nullptr, &timeout);
    printf("DEBUG: %s(..): %d = select(..)\n", fn.data(), rc);
    if (rc == 0) {
      continue;
    } else if (rc < 0) {
      const auto ec = errno;
      if (ec == EINTR) break; // signal occurred
      fprintf(stderr, "ERROR: %s(..): select(..): ec=%d; %s\n", fn.data() , ec, strerror(ec));
      return EXIT_FAILURE;
    }

    rc = read(fd, buf.data(), buf.size());
    if (rc < 0) {
      const auto ec = errno;
      fprintf(stderr, "ERROR: %s(..): reading tunnel pipe input failed: %d %s\n", fn.data() , ec, strerror(ec));
      return EXIT_FAILURE;
    }
    if (rc == 0) break; // eof
    if (rc > 0) {
      struct {
        socklen_t addr_len;
        sockaddr addr;
        size_t packet_size;
      } addr_buf;
      int bytes_rem = rc;
      if (static_cast<size_t>(rc) >= sizeof addr_buf) {
        bytes_rem -= sizeof addr_buf;
        memcpy(&addr_buf, buf.data(), sizeof addr_buf);
        const int sa_data_size = static_cast<int>(sizeof(addr_buf.addr.sa_data));
        printf("DEBUG: %s(..): struct addr_buf: addr_len: %u, addr.sa_data: \"%.*s\", data packet_size: %lu\n",
               fn.data(), addr_buf.addr_len, sa_data_size, addr_buf.addr.sa_data, addr_buf.packet_size);
      }
      printf("DEBUG: %s(..): struct addr_buf size: %lu, packet bytes received: %d, remaining bytes: %d\n",
             fn.data(), sizeof addr_buf, rc, bytes_rem);
    }
  }

  return EXIT_SUCCESS;
}