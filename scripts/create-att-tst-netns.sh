#!/bin/bash

# create a namespace
sudo ip netns add att-tst
ip netns list

# bring up the loopback interface on the new network namespace
sudo ip netns exec att-tst ip link set dev lo up
sudo ip netns exec att-tst sysctl -w net.ipv4.ping_group_range="0 2147483647"
sudo ip netns exec att-tst ip address

