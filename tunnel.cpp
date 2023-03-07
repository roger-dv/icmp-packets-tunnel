#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <array>
#include <unistd.h>
#include <memory>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

static int send_icmp_echo(const int pipe_out, const int dst_sockfd, const int rcv_dst_sockfd,
                          char * const buf, const size_t packet_size, const sockaddr_in &dst_addr);

int tunnel(int pipe_in, int pipe_out, sockaddr_un addr, socklen_t addr_len, const std::string_view dst_net_addr) {
  const std::string_view fn{__FUNCTION__};
  printf("DEBUG: %s(..) invoked\n", fn.data());

  auto const close_fd = [](int *p) {
    if (p != nullptr) {
      close(*p);
    }
  };
  // insure the socket descriptors arguments will get closed on exit
  std::unique_ptr<int, decltype(close_fd)> sp_fd_in{&pipe_in, close_fd};
  std::unique_ptr<int, decltype(close_fd)> sp_fd_out{&pipe_out, close_fd};

  // validate and convert the specified destination IPv4 address string into binary form
  struct in_addr dst;
  memset(&dst, 0, sizeof dst);
  if (inet_aton(dst_net_addr.data(), &dst) == 0) {
    fprintf(stderr, "ERROR: %s(..): inet_aton(__cp=\"%s\"): isn't a valid destination IP address\n",
            fn.data(), dst_net_addr.data());
    return EXIT_FAILURE;
  }

  struct sockaddr_in dst_addr;
  memset(&dst_addr, 0, sizeof dst_addr);
  dst_addr.sin_family = AF_INET;
  dst_addr.sin_addr = dst;

  int dst_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (dst_sockfd < 0) {
    const auto ec = errno;
    fprintf(stderr, "ERROR: %s(..): socket(..): ec=%d; %s\n", fn.data(), ec, strerror(ec));
    return EXIT_FAILURE;
  }
  std::unique_ptr<int, decltype(close_fd)> sp_dst_sockfd{&dst_sockfd, close_fd};

  int rcv_dst_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (rcv_dst_sockfd < 0) {
    const auto ec = errno;
    fprintf(stderr, "ERROR: socket(..): ec=%d; %s\n", ec, strerror(ec));
    return EXIT_FAILURE;
  }
  std::unique_ptr<int, decltype(close_fd)> sp_sockfd{&rcv_dst_sockfd, close_fd};

  // connect to the UDS socket on which the child process (packet sniffer on the network namespace)
  // will receive ICMP ECHO REPLY packets
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

  // proceed to indefinitely read ICMP ECHO packets per the UDS socket
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

      char *pcurr_buff = buf.data();
      int bytes_rem = rc;
      do {
        const int bytes_amt = bytes_rem;
        if (static_cast<size_t>(bytes_rem) >= sizeof addr_buf) {
          memcpy(&addr_buf, pcurr_buff, sizeof addr_buf);
          pcurr_buff += sizeof addr_buf;
          bytes_rem -= sizeof addr_buf;
          const int sa_data_size = static_cast<int>(sizeof(addr_buf.addr.sa_data));
          printf("DEBUG: %s(..): struct addr_buf: addr_len: %u, addr.sa_data: \"%.*s\", data packet_size: %lu\n",
                 fn.data(), addr_buf.addr_len, sa_data_size, addr_buf.addr.sa_data, addr_buf.packet_size);
        }
        printf("DEBUG: %s(..): struct addr_buf size: %lu, packet bytes received: %d, remaining bytes: %d\n",
               fn.data(), sizeof addr_buf, bytes_amt, bytes_rem);

        if (static_cast<size_t>(bytes_rem) >= addr_buf.packet_size) {
          if (send_icmp_echo(pipe_out, dst_sockfd, rcv_dst_sockfd, pcurr_buff, addr_buf.packet_size, dst_addr) != EXIT_SUCCESS)
          {
            return EXIT_FAILURE;
          }
          pcurr_buff += addr_buf.packet_size;
          bytes_rem -= addr_buf.packet_size;
        } else {
          fprintf(stderr, "WARN: %s(..): received ICMP ECHO packet not of expected size: %lu (actual: %d)\n",
                  fn.data(), addr_buf.packet_size, bytes_rem);
        }
      } while(bytes_rem > 0);
    }
  }

  return EXIT_SUCCESS;
}

static int send_icmp_echo(const int pipe_out, const int dst_sockfd, const int rcv_dst_sockfd,
                          char * const buf, const size_t packet_size, const sockaddr_in &dst_addr)
{
  const std::string_view fn{__FUNCTION__};

  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buf);
  const unsigned short iphdrlen = iph->ihl * 4;
  const struct icmphdr * const icmph = reinterpret_cast<struct icmphdr *>(buf + iphdrlen);
  if (icmph->type != ICMP_ECHO) {
    fprintf(stderr, "WARN: %s(..): is not an ICMP ECHO packet!", fn.data());
    return EXIT_SUCCESS;
  }

  sockaddr_in mut_addr = dst_addr;
  mut_addr.sin_port = 0;
  int rc = sendto(dst_sockfd, buf, packet_size, 0, reinterpret_cast<const sockaddr *>(&mut_addr), sizeof mut_addr);
  if (rc <= 0) {
    const auto ec = errno;
    fprintf(stderr, "ERROR: %s(..): sendto(__fd=%d,..): ec=%d; %s\n", fn.data(), dst_sockfd, ec, strerror(ec));
    return EXIT_FAILURE;
  }

  std::array<char, 2048> data{};

  fd_set read_set;
  memset(&read_set, 0, sizeof read_set);
  FD_SET(rcv_dst_sockfd, &read_set);

  // wait for a reply with a timeout
  struct timeval timeout = {0, 60}; // wait max 3 seconds for a reply
  for(bool is_first = true;;) {
    rc = select(rcv_dst_sockfd + 1, &read_set, nullptr, nullptr, &timeout);
    printf("DEBUG: %s(..): %d = select(..)\n", fn.data(), rc);
    if (rc == 0) {
      if (is_first) {
        printf("INFO: %s(..): Got no reply\n", fn.data());
      }
      break;
    } else if (rc < 0) {
      const auto ec = errno;
      if (ec == EINTR) {
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
      fprintf(stderr, "ERROR: %s(..): recvfrom(__fd=%d,..): ec=%d; %s\n", fn.data(), rcv_dst_sockfd, ec, strerror(ec));
      return EXIT_FAILURE;
    } else if (rc != 0) {
      if (static_cast<size_t>(rc) < sizeof(struct icmphdr)) {
        fprintf(stderr, "ERROR: %s(..): got short ICMP packet: %d bytes (expected %lu bytes)\n",
                fn.data(), rc, sizeof(struct icmphdr));
      } else {
        auto const prn_err = [](int fd, int ec) {
          fprintf(stderr, "ERROR: %s(..): write(__fd=%d..): ec=%d; %s\n", __FUNCTION__, fd, ec, strerror(ec));
        };
        struct {
          const socklen_t addr_len;
          const sockaddr addr;
          const size_t packet_size;
        } addr_buf{src_addr_len, src_addr, static_cast<size_t>(rc)};
        int n = write(pipe_out, &addr_buf, sizeof(addr_buf));
        if (n < 0) {
          prn_err(pipe_out, errno);
          return EXIT_FAILURE;
        }
        n = write(pipe_out, data.data(), rc);
        if (n < 0) {
          prn_err(pipe_out, errno);
          return EXIT_FAILURE;
        }
      }
    }
    timeout = {0, 60}; // now wait quarter of a second on select()
    is_first = false;
  }

  return EXIT_SUCCESS;
}