# Tunl

Program author: Roger D. Voss  
github username: roger-dv  
  
Copyright 2023 Roger D. Voss  
Source code of this project is under Apache License, Version 2.0


The program `tunl` is an exercise in network raw packet routing (via tunneling between two different network context).

The program is launched in the default network environment of the host computer, then it calls `fork()` to establish a child process. The child process establishes the command-line specified network namespace as its network.

The `tunl` program requires the Linux capabilities `CAP_SYS_ADMIN` and `CAP_NET_RAW`. The `setcap` Linux utility program is used to set these capabilities via this shell script:

```sh
# need to set Linux capabilities on tunl executable file (every time it's rebuilt)
sudo scripts/set-capabilities.sh tunl
```

The `tunl` program can then be executed like so:


```sh
./tunl my-netns-tst -ping 8.8.8.8 1> out.log 2>&1
```

The first argument will be the name of a Linux namespace network (the project contains a script for creating that). More on the `-ping` argument later. Both `stdout` and `stderr` console logging output are being redirected to a log file, `out.log`; the `tail` tool can be used to view the log file as the `tunl` program executes. (Logging is not optimized in this program but log output to a file should be more efficient than writing synchronously to the console.)

The upshot is that `tunl` runs two process instances of itself. The parent process will proceed to execute in the current, default network context. The child process will be executing in the network namespace context, called `my-netns-tst`.

To test the functionality of `tunl`, a command shell should be separately used to run the `ping` command in this manner:

```sh
sudo ip netns exec my-netns-tst ping -I lo 8.8.8.8
```

Here the `ping ` is executing in the context of the network namespace `my-netns-tst`, the catch is that IPv4 address `8.8.8.8` does not exist in that network namespace. Consequently the `ping` command attempts to send ICMP ECHO packets but there is never any reply; `ping` just sits there infinitely transmitting ECHO packets, which looks like so:

```sh
$ sudo ip netns exec my-netns-tst ping -I lo 8.8.8.8
ping: Warning: source address might be selected on device other than: lo
PING 8.8.8.8 (8.8.8.8) from 0.0.0.0 lo: 56(84) bytes of data.
```

The purpose of `tunl` is to sniff raw packets in the network namespace that `ping` is executing in, tunnel those packets to its parent process that runs in the default network of the host computer, write those raw ICMP ECHO packets in the default network (where the IPv4 `8.8.8.8` address does exist and will respond with ICMP ECHOREPLY packets). The parent process reads the return ICMP ECHOREPLY raw packet, tunnels that to the child process, where the ICMP ECHOREPLY raw packet is written to the network namespace (`my-netns-tst` per the illustrative example here).

The `ping` command will now see an ICMP ECHOREPLY and start writing acknowledgment to the console:

```sh
$ sudo ip netns exec my-netns-tst ping -I lo 8.8.8.8
ping: Warning: source address might be selected on device other than: lo
PING 8.8.8.8 (8.8.8.8) from 0.0.0.0 lo: 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=364 ttl=118 time=24.3 ms
64 bytes from 8.8.8.8: icmp_seq=365 ttl=118 time=23.8 ms
64 bytes from 8.8.8.8: icmp_seq=366 ttl=118 time=23.4 ms
64 bytes from 8.8.8.8: icmp_seq=367 ttl=118 time=24.0 ms
64 bytes from 8.8.8.8: icmp_seq=368 ttl=118 time=23.8 ms
64 bytes from 8.8.8.8: icmp_seq=369 ttl=118 time=24.1 ms
```

## How `tunl` works:

Each of the two `tunl` processes (as described above) in turn employ two worker task (running on respective dedicated thread).

The `tunl` child process, running in the network name space, has:

- **sniff** task
- **reply** task

The `tunl` parent process, running in the default network context of the host computer, has:

- **tunnel** task
- **relay** task

The **sniff** task reads raw packets from the network namespace, it checks and validates ICMP packets; when it sees an ICMP ECHO packet, it writes that raw packet into a UDS socket connection.

The **tunnel** task, running in the parent process, reads from said UDS socket, obtains the raw ICMP ECHO packet, and writes it to the default network.

The **relay** task, running in the parent process, reads raw packets from the default network, filtering for only ICMP packets. When it sees an ICMP ECHOREPLY packet, it writes that to a second UDS socket connection.

The **reply** task, which is running in the child process, reads the raw ICMP ECHOREPLY packet from that second UDS socket connection, and then writes that raw packet into the network namespace (e.g., the `my-netns-tst` netns per this example).

The `ping` command sees the raw ICMP ECHOREPLY packets written by the **reply** task and takes them to be the response to the ICMP ECHO packets that it has been dutifully emitting.

That is the point of the `tunl` program - to tunnel ICMP packets traffic between two different network context.

### Source code correlation to above described task:

These are the source files of `tunl`:

```
main.cpp
sniff.cpp
reply.cpp
tunnel.cpp
relay.cpp
```

The source file name corresponds to the task name, so, for instance, `sniff.cpp` is the implementation  for the **sniff** task, etc.

The `main.cpp` source file does startup stuff, invokes `fork()`, establishes the `my-netns-tst` network namespace per the child process, initiates task threads, and uses futures to wait on said task threads. The parent process also uses `waitpid()` to wait on the child process to complete. The code following after the `main()` function are various utility functions.

### Reading and writing raw network packets

Sockets for reading (packet sniffing) raw packets are created like so:

```C
int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
```

Sockets for writing raw packets are created thusly:

```C
int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
```

*NOTE: The Linux capability `CAP_NET_RAW` is required for invoking `socket()` with the `IPPROTO_RAW` protocol.*

## Linux network namespace scripts

The scripts for creating and deleting a network namespace used per this working example are:

```
scripts/create-tst-netns.sh
scripts/delete-tst-netns.sh
```

Both of these scripts must be invoked with `sudo` and passed the network namespace name as an argument, like so:

```sh
sudo scripts/create-tst-netns.sh my-netns-tst
```

Here are the contents of the create script:

```sh
#!/bin/bash

if [ "${EUID}" != "0" ]; then
  echo "ERROR: must be root user"
  exit 1
fi

if [ -z "${1}" ]; then
  echo "ERROR: must supply network namespace name as command line argument"
  exit 1
fi

NETNS_NAME="${1}"

# create a namespace
ip netns add "${NETNS_NAME}"
ip netns list

# bring up the loopback interface on the new network namespace
ip netns exec "${NETNS_NAME}" ip link set dev lo up
ip netns exec "${NETNS_NAME}" sysctl -w net.ipv4.ping_group_range="0 2147483647"
ip netns exec "${NETNS_NAME}" ip address
```

The delete script:

```sh
#!/bin/bash

if [ "${EUID}" != "0" ]; then
  echo "ERROR: must be root user"
  exit 1
fi

if [ -z "${1}" ]; then
  echo "ERROR: must supply network namespace name as command line argument"
  exit 1
fi

NETNS_NAME="${1}"

# delete the network namespace
ip netns delete "${NETNS_NAME}" 
ip netns list
```

## Compiler used for building `tunl`

The compiler gcc/g++ version 12.1 was used to build the `tunl` project. This compiler has good C++17 compliance and significant support for C++20 (but is not complete, e.g., does not support format yet).

The `tunl` source code is C++17 compliant except for the use of `std::span`; it proved necessary to set the `-std=gnu++20` compiler option (refer to `CMakeLists.txt`) in order to use `std::span`.

The `tunl` program requires the use of `libcap` for its Linux capabilities API. The `libcap` package may need to be installed; this example is for Debian/Ubuntu distros:

```sh
sudo apt-get -y install libcap-dev
```