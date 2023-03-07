#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <array>
#include <memory>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

static int write_packet(const int fd, char *data, const size_t datasize, const sockaddr& addr, const socklen_t addr_len);

int relay(int pipe_out, sockaddr_un addr, socklen_t addr_len) {
  const std::string_view fn{__FUNCTION__};
  printf("INFO: %s(..) invoked\n", fn.data());

  auto const close_fd = [](int *p) {
    if (p != nullptr) {
      close(*p);
    }
  };
  // insure the socket descriptors arguments will get closed on exit
  std::unique_ptr<int, decltype(close_fd)> sp_fd_out{&pipe_out, close_fd};

  // connect to the UDS socket on which the child process (packet sniffer on the network namespace)
  // will receive ICMP ECHO REPLY packets
  for (;;) {
    if (connect(pipe_out, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == -1) {
      const auto ec = errno;
      fprintf(stderr, "WARN: %s(..): connect(__fd=%d,addr=\"%s\"..): ec=%d; %s\n",
              fn.data(), pipe_out, addr.sun_path, ec, strerror(ec));
      sleep(3);
      continue;
    }
    break;
  }

  int rcv_dst_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (rcv_dst_sockfd < 0) {
    const auto ec = errno;
    fprintf(stderr, "ERROR: socket(..): ec=%d; %s\n", ec, strerror(ec));
    return EXIT_FAILURE;
  }
  std::unique_ptr<int, decltype(close_fd)> sp_sockfd{&rcv_dst_sockfd, close_fd};

  std::array<char, 2048> data{};

  bool is_signal = false;
  while (!is_signal) {
    fd_set read_set;
    memset(&read_set, 0, sizeof read_set);
    FD_SET(rcv_dst_sockfd, &read_set);

    // wait for a reply with a timeout
    struct timeval timeout = {3, 0}; // wait max 3 seconds for a reply
    for (bool is_first = true;;) {
      int rc = select(rcv_dst_sockfd + 1, &read_set, nullptr, nullptr, &timeout);
//      printf("DEBUG: %s(..): %d = select(..)\n", fn.data(), rc);
      if (rc == 0) {
        if (is_first) {
//          printf("DEBUG: %s(..): Got no reply\n", fn.data());
        }
        break;
      } else if (rc < 0) {
        const auto ec = errno;
        if (ec == EINTR) {
          is_signal = true;
          break; // signal occurred
        }
        fprintf(stderr, "ERROR: %s(..): select(..): ec=%d; %s\n", fn.data(), ec, strerror(ec));
        return EXIT_FAILURE;
      }

      sockaddr src_addr;
      memset(&src_addr, 0, sizeof src_addr);
      socklen_t src_addr_len = 0;
      memset(data.data(), 0, sizeof(struct icmphdr));
      rc = recvfrom(rcv_dst_sockfd, data.data(), data.size(), 0, &src_addr, &src_addr_len);
      printf("DEBUG: %s(..): %d = recvfrom(..)\n", fn.data(), rc);
      if (rc < 0) { // check and handle error condition
        const auto ec = errno;
        fprintf(stderr, "ERROR: %s(..): recvfrom(__fd=%d,..): ec=%d; %s\n", fn.data(), rcv_dst_sockfd, ec,
                strerror(ec));
        return EXIT_FAILURE;
      } else if (rc != 0) {
        if (static_cast<size_t>(rc) < sizeof(struct icmphdr)) {
          fprintf(stderr, "ERROR: %s(..): got short ICMP packet: %d bytes (expected %lu bytes)\n",
                  fn.data(), rc, sizeof(struct icmphdr));
        } else {
          if (write_packet(pipe_out, data.data(), rc, src_addr, src_addr_len) != EXIT_SUCCESS) {
            return EXIT_SUCCESS;
          }
        }
      }
      timeout = {0, 250}; // now wait quarter of a second on select()
      is_first = false;
    }
  }

  return EXIT_SUCCESS;
}

static int write_packet(const int fd, char *data, const size_t datasize, const sockaddr& addr, const socklen_t addr_len) {
  struct {
    const socklen_t addr_len;
    const sockaddr addr;
    const size_t packet_size;
  } addr_buf{addr_len, addr, datasize};

  const size_t total_buf_size = sizeof addr_buf + datasize;
  char * const buf = reinterpret_cast<char*>(alloca(total_buf_size));
  memcpy(buf, &addr_buf, sizeof addr_buf);
  memcpy(buf + sizeof addr_buf, data, datasize);

  int n = write(fd, buf, total_buf_size);
  if (n < 0) {
    const auto ec = errno;
    fprintf(stderr, "ERROR: %s(..): write(__fd=%d..): ec=%d; %s\n", __FUNCTION__, fd, ec, strerror(ec));
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}