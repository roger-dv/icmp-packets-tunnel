#!/bin/bash

# delete the network namespace
sudo ip netns delete att-tst
ip netns list
