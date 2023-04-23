/* sniff.cpp

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
#include <csignal>
#include <string_view>
#include <memory>
#include <span>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include "spdlog/logger.h"

static int process_packet(const long sequence, const std::span<char> buffer, const size_t packet_size, const int sockfd,
                          const sockaddr &src_addr, const socklen_t src_addr_len, const int pipe_out);
static int print_icmp_packet(const long sequence, const std::span<char> buffer, const size_t packet_size,
                             const sockaddr &src_addr, const socklen_t src_addr_len, const int pipe_out);
static void print_tcp_packet(const std::span<char> buffer);
static void print_udp_packet(const std::span<char> buffer);

extern std::shared_ptr<spdlog::logger> logger;
static int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;
static auto c_start = std::chrono::high_resolution_clock::now();

int sniff(int pipe_out, sockaddr_un addr, [[maybe_unused]] socklen_t addr_len) {
  const std::string_view fn{__FUNCTION__};
  logger->info("{}(..) invoked", fn.data());

  auto const cleanup_sockfd = [](const int* p) {
    if (p != nullptr) {
      close(*p);
      logger->info("{}(..): close(__fd={}) called", __FUNCTION__, *p);
    }
  };

  std::unique_ptr<const int, decltype(cleanup_sockfd)> sp_pipe_out_fd{&pipe_out, cleanup_sockfd};

  for(;;) {
    if (connect(pipe_out, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == -1) {
      const auto ec = errno;
      logger->warn("{}(..): connect(__fd={},addr=\"{}\",..): ec={}; {}",
                   fn.data(), pipe_out, addr.sun_path, ec, strerror(ec));
      sleep(3);
      continue;
    }
    break;
  }

  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    const auto ec = errno;
    logger->error("{}(..): socket(..): ec={}; {}", fn.data(), ec, strerror(ec));
    return EXIT_FAILURE;
  }
  std::unique_ptr<int, decltype(cleanup_sockfd)> sp_sockfd{&sockfd, cleanup_sockfd};

  std::array<char, 2048> data;

  c_start = std::chrono::high_resolution_clock::now();
  long sequence = 0;
  bool is_signal = false;
  while (!is_signal) {
    sequence++;
    fd_set read_set;
    memset(&read_set, 0, sizeof read_set);
    FD_SET(sockfd, &read_set);

    // wait for a reply with a timeout
    struct timeval timeout = {3, 0}; // wait max 3 seconds for a reply
    for(bool is_first = true;;) {
      int rc = select(sockfd + 1, &read_set, nullptr, nullptr, &timeout);
//      logger->debug("{}(..): {} = select(..)", fn.data(), rc);
      if (rc == 0) {
        if (is_first) {
          fprintf(stdout, "INFO: %s(..): Got no packets\n", fn.data());
          fflush(stdout);
        }
        break;
      } else if (rc < 0) {
        const auto ec = errno;
        if (ec == EINTR) {
          is_signal = true;
          break; // signal occurred
        }
        logger->error("{}(..): select(..): ec={}; {}", fn.data(), ec, strerror(ec));
        return EXIT_FAILURE;
      }

      sockaddr src_addr;
      memset(&src_addr, 0, sizeof src_addr);
      socklen_t src_addr_len = 0;
      memset(data.data(), 0, sizeof(struct icmphdr));
      rc = recvfrom(sockfd, data.data(), data.size(), 0, &src_addr, &src_addr_len);
//      logger->debug("{}(..): {} = recvfrom(..)", fn.data(), rc);
      if (rc < 0) { // check and handle error condition
        const auto ec = errno;
        logger->error("{}(..): recvfrom(__fd={},..): ec={}; {}", fn.data(), sockfd, ec, strerror(ec));
        return EXIT_FAILURE;
      } else if (rc > 0) {
        if (static_cast<size_t>(rc) < sizeof(struct iphdr)) {
          logger->warn("{}(..): got too short raw packet: {} bytes (expected minimum iphdr {} bytes)",
                       fn.data(), rc, sizeof(struct iphdr));
        } else {
          const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(data.data());
          const unsigned short icmp_pck_len = iph->ihl * 4 + sizeof(struct icmphdr);
          if (rc < icmp_pck_len) {
            logger->error("{}(..): got too short ICMP packet: {} bytes (expected minimum {} bytes)",
                          fn.data(), rc, icmp_pck_len);
          } else {
            if (process_packet(sequence, data, rc, sockfd, src_addr, src_addr_len, pipe_out) != EXIT_SUCCESS) {
              return EXIT_FAILURE;
            }
          }
        }
      }
      timeout = {0, 250}; // now wait quarter of a second on select()
      is_first = false;
    }
  }

  return EXIT_SUCCESS;
}

static int process_packet(const long sequence, const std::span<char> buffer, const size_t packet_size, const int sockfd,
                          const sockaddr &src_addr, const socklen_t src_addr_len, const int pipe_out)
{
  int rc = EXIT_SUCCESS;
  //Get the IP Header part of this packet
  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buffer.data());
  ++total;
  switch (iph->protocol) { // Check the Protocol and do accordingly...
    case 1:  // ICMP Protocol
      ++icmp;
      if (static_cast<size_t>(packet_size) < sizeof(struct icmphdr)) { // check for truncated packet (would be unexpected)
        logger->error("{}(..) recvfrom(__fd={},..): got short ICMP packet - {} bytes (expected 'struct icmphdr' {} bytes)",
                      __FUNCTION__ , sockfd, packet_size, static_cast<unsigned int>(sizeof(struct icmphdr)));
      } else {
        rc = print_icmp_packet(sequence, buffer, packet_size, src_addr, src_addr_len, pipe_out);
      }
      break;
    case 2:  // IGMP Protocol
      ++igmp;
      break;
    case 6:  // TCP Protocol
      ++tcp;
      print_tcp_packet(buffer);
      break;
    case 17: // UDP Protocol
      ++udp;
      print_udp_packet(buffer);
      break;
    default: // Some Other Protocol like ARP etc.
      ++others;
      logger->warn("Other packet protocol: {}", iph->protocol);
      break;
  }
  const auto c_curr = std::chrono::high_resolution_clock::now();
  const auto diff = std::chrono::duration_cast<std::chrono::seconds>(c_curr - c_start).count();
  if (diff >= 15) { // every 15 seconds print out these totals
    c_start = c_curr;
    logger->info("sniff: TCP : {}   UDP : {}   ICMP : {}   IGMP : {}   Others : {}   Total : {}",
                 tcp, udp, icmp, igmp, others, total);
  }

  return rc;
}

std::string_view icmp_type_to_str(const unsigned int type) {
  switch(type) {
    case ICMP_ECHOREPLY:      return "ICMP_ECHOREPLY";      // Echo Reply
    case ICMP_DEST_UNREACH:   return "ICMP_DEST_UNREACH";   // Destination Unreachable
    case ICMP_SOURCE_QUENCH:  return "ICMP_SOURCE_QUENCH";  // Source Quench
    case ICMP_REDIRECT:       return "ICMP_REDIRECT";       // Redirect (change route)
    case ICMP_ECHO:           return "ICMP_ECHO";           // Echo Request
    case ICMP_TIME_EXCEEDED:  return "ICMP_TIME_EXCEEDED";  // Time Exceeded
    case ICMP_PARAMETERPROB:  return "ICMP_PARAMETERPROB";  // Parameter Problem
    case ICMP_TIMESTAMP:      return "ICMP_TIMESTAMP";      // Timestamp Request
    case ICMP_TIMESTAMPREPLY: return "ICMP_TIMESTAMPREPLY"; // Timestamp Reply
    case ICMP_INFO_REQUEST:   return "ICMP_INFO_REQUEST";   // Information Request
    case ICMP_INFO_REPLY:     return "ICMP_INFO_REPLY";     // Information Reply
    case ICMP_ADDRESS:        return "ICMP_ADDRESS";        // Address Mask Request
    case ICMP_ADDRESSREPLY:   return "ICMP_ADDRESSREPLY";   // Address Mask Reply
    default:                  return "unknown";
  }
}

static int print_icmp_packet(const long sequence, const std::span<char> buffer, const size_t packet_size,
                             const sockaddr &src_addr, const socklen_t src_addr_len, const int pipe_out)
{
  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buffer.data());
  const unsigned short iphdrlen = iph->ihl * 4;
  const struct icmphdr * const icmph = reinterpret_cast<struct icmphdr *>(buffer.data() + iphdrlen);
  const auto type = static_cast<unsigned int>(icmph->type);
  const auto type_str = icmp_type_to_str(type);
  logger->info("sniff: ICMP Header | -Type : {} : {}", type, type_str.data());

  if (type == ICMP_ECHOREPLY) {
    std::array<char, 1024> strbuf{};
    snprintf(strbuf.data(), strbuf.size(),
             "sniff: ICMP Reply: icmphdr id=0x%X, icmphdr sequence=0x%X (%d); iteration sequence=0x%lX (%ld)",
              icmph->un.echo.id, icmph->un.echo.sequence, icmph->un.echo.sequence, sequence, sequence);
    logger->info(strbuf.data());
  } else if (type == ICMP_ECHO) {
    struct {
      const socklen_t addr_len;
      const sockaddr addr;
      const size_t packet_size;
    } addr_buf{src_addr_len, src_addr, packet_size};

    const size_t total_buf_size = sizeof addr_buf + packet_size;
    char * const buf = reinterpret_cast<char*>(alloca(total_buf_size));
    memcpy(buf, &addr_buf, sizeof addr_buf);
    memcpy(buf + sizeof addr_buf, buffer.data(), packet_size);

    int rc = write(pipe_out, buf, total_buf_size);
    if (rc < 0) {
      const auto ec = errno;
      logger->error("{}(..): write(__fd={}..): ec={}; {}", __FUNCTION__, pipe_out, ec, strerror(ec));
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}

static void print_tcp_packet(const std::span<char> buffer) {
  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buffer.data());
  const unsigned short iphdrlen = iph->ihl * 4;
  const struct tcphdr * const tcph = reinterpret_cast<struct tcphdr *>(buffer.data() + iphdrlen);
  std::array<char, 2048> strbuf{};
  snprintf(strbuf.data(), strbuf.size(),
           "sniff: TCP Header\n"
           "   |-Source Port        : %u\n"
           "   |-Destination Port   : %u\n"
           "   |-Sequence Number    : %u\n"
           "   |-Acknowledge Number : %u\n"
           "   |-Header Length      : %u DWORDS or %u BYTES",
           ntohs(tcph->source), ntohs(tcph->dest), ntohl(tcph->seq), ntohl(tcph->ack_seq),
           static_cast<unsigned int>(tcph->doff), static_cast<unsigned int>(tcph->doff * 4));
  logger->info(strbuf.data());
}

static void print_udp_packet(const std::span<char> buffer) {
  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buffer.data());
  const unsigned short iphdrlen = iph->ihl * 4;
  const struct udphdr * const udph = reinterpret_cast<struct udphdr *>(buffer.data() + iphdrlen);
  std::array<char, 2048> strbuf{};
  snprintf(strbuf.data(), strbuf.size(),
           "sniff: UDP Header\n"
           "   |-Source Port      : %d\n"
           "   |-Destination Port : %d\n"
           "   |-UDP Length       : %d", ntohs(udph->source), ntohs(udph->dest), ntohs(udph->len));
  logger->info(strbuf.data());
}