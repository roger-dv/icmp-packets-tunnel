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
