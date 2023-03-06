#include <cstdlib>
#include <cstdio>
#include <csignal>
#include <memory>
#include <cstring>
#include <span>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>

static void process_packet(const std::span<char> buffer, const int sockfd, const int packet_size, const long sequence);
static void print_icmp_packet_helper(const struct icmphdr * const icmph, const long sequence);
static void print_icmp_packet(const std::span<char> buffer, const long sequence);
static void print_tcp_packet(const std::span<char> buffer);
static void print_udp_packet(const std::span<char> buffer);

static int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;
static auto c_start = std::chrono::high_resolution_clock::now();

int sniff(int pipe_out) {
  const std::string_view fn{__FUNCTION__};
  fprintf(stderr, "DEBUG: %s(..) invoked\n", fn.data());
  auto const close_fstream = [](FILE**p) {
    if (p != nullptr && *p != nullptr) {
      fclose(*p);
    }
  };
  FILE *fstream_out = fdopen(pipe_out, "wb");
  std::unique_ptr<FILE*, decltype(close_fstream)> sp_fstream_out{&fstream_out, close_fstream};

  auto const cleanup_sockfd = [](const int* p) {
    if (p != nullptr) {
      close(*p);
      fprintf(stderr, "INFO: close(__fd=%d) called\n", *p);
    }
  };
  const int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    const auto ec = errno;
    fprintf(stderr, "ERROR: socket(..): ec=%d; %s\n", ec, strerror(ec));
    return EXIT_FAILURE;
  }
  std::unique_ptr<const int, decltype(cleanup_sockfd)> sp_sockfd{&sockfd, cleanup_sockfd};

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
//      printf("DEBUG: %d = select(..)\n", rc);
      if (rc == 0) {
        if (is_first) {
          fputs("INFO: Got no packets\n", fstream_out);
          fprintf(stderr, "DEBUG: %s(..): Got no packets\n", fn.data());
        }
        break;
      } else if (rc < 0) {
        const auto ec = errno;
        if (ec == EINTR) {
          is_signal = true;
          break; // signal occurred
        }
        fprintf(stderr, "ERROR: select(..): ec=%d; %s\n", ec, strerror(ec));
        return EXIT_FAILURE;
      }

      // we don't care about the sender address in this situation...
      memset(data.data(), 0, sizeof(struct icmphdr));
      rc = recvfrom(sockfd, data.data(), data.size(), 0, nullptr, nullptr);
//      printf("DEBUG: %d = recvfrom(..)\n", rc);
      if (rc < 0) { // check and handle error condition
        const auto ec = errno;
        fprintf(stderr, "ERROR: recvfrom(__fd=%d,..): ec=%d; %s\n", sockfd, ec, strerror(ec));
        return EXIT_FAILURE;
      } else if (rc != 0) {
        process_packet(data, sockfd, rc, sequence);
      }
      timeout = {0, 250}; // now wait quarter of a second on select()
      is_first = false;
    }
  }

  return EXIT_SUCCESS;
}

static void process_packet(const std::span<char> buffer, const int sockfd, const int packet_size, const long sequence) {
  //Get the IP Header part of this packet
  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buffer.data());
  ++total;
  switch (iph->protocol) { // Check the Protocol and do accordingly...
    case 1:  // ICMP Protocol
      ++icmp;
      if (static_cast<size_t>(packet_size) < sizeof(struct icmphdr)) { // check for truncated packet (would be unexpected)
        fprintf(stderr, "ERROR: recvfrom(__fd=%d,..): got short ICMP packet - %d bytes (expected 'struct icmphdr' %u bytes)\n",
                sockfd, packet_size, static_cast<unsigned int>(sizeof(struct icmphdr)));
      }
      print_icmp_packet(buffer, sequence);
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
      printf("Other packet protocol: %d\n", iph->protocol);
      break;
  }
  const auto c_curr = std::chrono::high_resolution_clock::now();
  const auto diff = std::chrono::duration_cast<std::chrono::seconds>(c_curr - c_start).count();
  if (diff >= 15) { // every 15 seconds print out these totals
    c_start = c_curr;
    fprintf(stdout, "TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n",
           tcp, udp, icmp, igmp, others, total);
  }
}

static std::string_view icmp_type_to_str(const unsigned int type) {
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

static void print_icmp_packet_helper(const struct icmphdr * const icmph, const long sequence) {
  const auto type = static_cast<unsigned int>(icmph->type);
  const auto type_str = icmp_type_to_str(type);
  fprintf(stdout, "ICMP Header | -Type : %u : %s%49c\n", type, type_str.data(), ' ');
  if (type == ICMP_ECHOREPLY) {
    fprintf(stdout, "ICMP Reply: icmphdr id=0x%X, icmphdr sequence=0x%X (%d); iteration sequence=0x%lX (%ld)%29c\n",
           icmph->un.echo.id, icmph->un.echo.sequence, icmph->un.echo.sequence, sequence, sequence, ' ');
  }
}

static void print_icmp_packet(const std::span<char> buffer, const long sequence) {
  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buffer.data());
  const unsigned short iphdrlen = iph->ihl * 4;
  const struct icmphdr * const icmph = reinterpret_cast<struct icmphdr *>(buffer.data() + iphdrlen);
  print_icmp_packet_helper(icmph, sequence);
}

static void print_tcp_packet(const std::span<char> buffer) {
  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buffer.data());
  const unsigned short iphdrlen = iph->ihl * 4;
  const struct tcphdr * const tcph = reinterpret_cast<struct tcphdr *>(buffer.data() + iphdrlen);
  printf("TCP Header\n");
  printf("   |-Source Port        : %u\n",ntohs(tcph->source));
  printf("   |-Destination Port   : %u\n",ntohs(tcph->dest));
  printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
  printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
  printf("   |-Header Length      : %u DWORDS or %u BYTES\n" ,
         static_cast<unsigned int>(tcph->doff), static_cast<unsigned int>(tcph->doff * 4));
}

static void print_udp_packet(const std::span<char> buffer) {
  const struct iphdr * const iph = reinterpret_cast<struct iphdr *>(buffer.data());
  const unsigned short iphdrlen = iph->ihl * 4;
  const struct udphdr * const udph = reinterpret_cast<struct udphdr *>(buffer.data() + iphdrlen);
  printf("UDP Header\n");
  printf("   |-Source Port      : %d\n" , ntohs(udph->source));
  printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
  printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
}