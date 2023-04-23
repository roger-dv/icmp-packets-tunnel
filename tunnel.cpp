/* tunnel.cpp

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
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <array>
#include <string_view>
#include <memory>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include "spdlog/logger.h"

extern std::shared_ptr<spdlog::logger> logger;
static int send_icmp_echo(const int dst_sockfd, char * const buf, const size_t packet_size, const sockaddr_in &dst_addr);

int tunnel(int pipe_in, const std::string_view dst_net_addr) {
  const std::string_view fn{__FUNCTION__};
  logger->info("{}(..) invoked", fn.data());

  auto const close_fd = [](int *p) {
    if (p != nullptr) {
      close(*p);
    }
  };
  // insure the socket descriptors arguments will get closed on exit
  std::unique_ptr<int, decltype(close_fd)> sp_fd_in{&pipe_in, close_fd};

  // validate and convert the specified destination IPv4 address string into binary form
  struct in_addr dst;
  memset(&dst, 0, sizeof dst);
  if (inet_aton(dst_net_addr.data(), &dst) == 0) {
    logger->error("{}(..): inet_aton(__cp=\"{}\"): isn't a valid destination IP address", fn.data(), dst_net_addr.data());
    return EXIT_FAILURE;
  }

  struct sockaddr_in dst_addr;
  memset(&dst_addr, 0, sizeof dst_addr);
  dst_addr.sin_family = AF_INET;
  dst_addr.sin_addr = dst;

  int dst_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (dst_sockfd < 0) {
    const auto ec = errno;
    logger->error("{}(..): socket(..): ec={}; {}", fn.data(), ec, strerror(ec));
    return EXIT_FAILURE;
  }
  std::unique_ptr<int, decltype(close_fd)> sp_dst_sockfd{&dst_sockfd, close_fd};

  int rcv_dst_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (rcv_dst_sockfd < 0) {
    const auto ec = errno;
    logger->error("socket(..): ec={}; {}", ec, strerror(ec));
    return EXIT_FAILURE;
  }
  std::unique_ptr<int, decltype(close_fd)> sp_sockfd{&rcv_dst_sockfd, close_fd};

  if (listen(pipe_in, 5) == -1) {
    const auto ec = errno;
    logger->error("{}(..): listen(__fd={},..): ec={}; {}", fn.data(), pipe_in, ec, strerror(ec));
    return EXIT_FAILURE;
  }

  int fd = accept(pipe_in, nullptr, nullptr);
  if (fd == -1) {
    const auto ec = errno;
    logger->warn("{}(..): accept(__fd={},..): ec={}; {}", fn.data(), pipe_in, ec, strerror(ec));
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
//    logger->debug("{}(..): {} = select(..)", fn.data(), rc);
    if (rc == 0) {
      continue;
    } else if (rc < 0) {
      const auto ec = errno;
      if (ec == EINTR) break; // signal occurred
      logger->error("{}(..): select(..): ec={}; {}", fn.data() , ec, strerror(ec));
      return EXIT_FAILURE;
    }

    rc = read(fd, buf.data(), buf.size());
    if (rc < 0) {
      const auto ec = errno;
      logger->error("{}(..): reading tunnel pipe input failed: {} {}", fn.data() , ec, strerror(ec));
      return EXIT_FAILURE;
    }
    if (rc == 0) break; // eof
    struct {
      socklen_t addr_len;
      sockaddr addr;
      size_t packet_size;
    } addr_buf;
    char *pcurr_buff = buf.data();
    int bytes_rem = rc;
    std::array<char, 2048> strbuf{};
    do {
      const int bytes_amt = bytes_rem;
      if (static_cast<size_t>(bytes_rem) >= sizeof addr_buf) {
        memcpy(&addr_buf, pcurr_buff, sizeof addr_buf);
        pcurr_buff += sizeof addr_buf;
        bytes_rem -= sizeof addr_buf;
        const int sa_data_size = static_cast<int>(sizeof(addr_buf.addr.sa_data));
        snprintf(strbuf.data(), strbuf.size(),
                 "%s(..): struct addr_buf: addr_len: %u, addr.sa_data: \"%.*s\", data packet_size: %lu",
                 fn.data(), addr_buf.addr_len, sa_data_size, addr_buf.addr.sa_data, addr_buf.packet_size);
        logger->debug(strbuf.data());
      }
      snprintf(strbuf.data(), strbuf.size(),
               "%s(..): struct addr_buf size: %lu, packet bytes received: %d, remaining bytes: %d",
               fn.data(), sizeof addr_buf, bytes_amt, bytes_rem);
      logger->debug(strbuf.data());

      if (static_cast<size_t>(bytes_rem) >= addr_buf.packet_size) {
        if (send_icmp_echo(dst_sockfd, pcurr_buff, addr_buf.packet_size, dst_addr) != EXIT_SUCCESS) {
          return EXIT_FAILURE;
        }
        pcurr_buff += addr_buf.packet_size;
        bytes_rem -= addr_buf.packet_size;
      } else {
        logger->error("{}(..): received ICMP ECHO packet not of expected size: {} (actual: {})",
                      fn.data(), addr_buf.packet_size, bytes_rem);
      }
    } while (bytes_rem > 0);
  }

  return EXIT_SUCCESS;
}

static int send_icmp_echo(const int dst_sockfd, char * const buf, const size_t packet_size, const sockaddr_in &dst_addr) {
  const std::string_view fn{__FUNCTION__};

  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buf);
  const unsigned short iphdrlen = iph->ihl * 4;
  const struct icmphdr * const icmph = reinterpret_cast<struct icmphdr *>(buf + iphdrlen);
  if (icmph->type != ICMP_ECHO) {
    logger->warn("{}(..): is not an ICMP ECHO packet!", fn.data());
    return EXIT_SUCCESS;
  }

  sockaddr_in mut_addr = dst_addr;
  mut_addr.sin_port = 0;
  int rc = sendto(dst_sockfd, buf, packet_size, 0, reinterpret_cast<const sockaddr *>(&mut_addr), sizeof mut_addr);
  if (rc <= 0) {
    const auto ec = errno;
    logger->error("{}(..): sendto(__fd={},..): ec={}; {}", fn.data(), dst_sockfd, ec, strerror(ec));
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}