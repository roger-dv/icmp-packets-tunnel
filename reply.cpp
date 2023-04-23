/* reply.cpp

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
#include <cstring>
#include <array>
#include <string_view>
#include <memory>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include "spdlog/logger.h"

extern std::shared_ptr<spdlog::logger> logger;
extern std::string_view icmp_type_to_str(const unsigned int type);
static int send_icmp_echo_reply(char * const buf, const size_t packet_size, const int dst_sockfd,
                                sockaddr &addr, const socklen_t addr_len);

int reply(int pipe_in) {
  const std::string_view fn{__FUNCTION__};
  logger->info("{}(..) invoked", fn.data());

  auto const close_fd = [](int *p) {
    if (p != nullptr) {
      close(*p);
    }
  };
  std::unique_ptr<int, decltype(close_fd)> sp_fd_in{&pipe_in, close_fd};

  int dst_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (dst_sockfd < 0) {
    const auto ec = errno;
    logger->error("{}(..): socket(..): ec={}; {}", fn.data(), ec, strerror(ec));
    return EXIT_FAILURE;
  }
  std::unique_ptr<int, decltype(close_fd)> sp_dst_sockfd{&dst_sockfd, close_fd};

  if (listen(pipe_in, 5) == -1) {
    const auto ec = errno;
    logger->error("{}(..): listen(__fd={},..): ec={}; {}", fn.data(), pipe_in, ec, strerror(ec));
    return EXIT_FAILURE;
  }

  int fd = accept(pipe_in, nullptr, nullptr);
  if (fd == -1) {
    const auto ec = errno;
    logger->error("{}(..): accept(__fd={},..): ec={}; {}", fn.data(), pipe_in, ec, strerror(ec));
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
      logger->error("{}(..): reading tunnel pipe reply input failed: {} {}", fn.data() , ec, strerror(ec));
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
        if (send_icmp_echo_reply(pcurr_buff, addr_buf.packet_size, dst_sockfd, addr_buf.addr, addr_buf.addr_len) !=
            EXIT_SUCCESS) {
          return EXIT_FAILURE;
        }
        pcurr_buff += addr_buf.packet_size;
        bytes_rem -= addr_buf.packet_size;
      } else {
        logger->error("{}(..): received ICMP packet not of expected size: {} (actual: {})",
                      fn.data(), addr_buf.packet_size, bytes_rem);
      }
    } while (bytes_rem > 0);
  }

  return EXIT_SUCCESS;
}

static int send_icmp_echo_reply(char * const buf, const size_t packet_size, const int dst_sockfd,
                                sockaddr &addr, const socklen_t addr_len)
{
  const std::string_view fn{__FUNCTION__};

  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buf);
  const unsigned short iphdrlen = iph->ihl * 4;
  const struct icmphdr * const icmph = reinterpret_cast<struct icmphdr *>(buf + iphdrlen);
  const auto type = static_cast<unsigned int>(icmph->type);
  const auto type_str = icmp_type_to_str(type);
  logger->debug("{}(..): ICMP Header | -Type : {} : {}", fn.data(), type, type_str.data());

  if (type == ICMP_ECHOREPLY) {
    int rc = sendto(dst_sockfd, buf, packet_size, 0, &addr, addr_len);
    if (rc <= 0) {
      const auto ec = errno;
      logger->error("{}(..): sendto(__fd={},..): ec={}; {}", fn.data(), dst_sockfd, ec, strerror(ec));
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}