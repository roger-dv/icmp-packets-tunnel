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
