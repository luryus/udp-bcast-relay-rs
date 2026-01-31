#!/bin/bash
set -e

# Setup network namespaces for UDP relay testing
# This script creates two isolated network namespaces connected to the
# default namespace via veth pairs.

echo "Creating network namespaces..."

# Create namespaces
ip netns add ns_sender
ip netns add ns_receiver

# Create veth pairs
ip link add veth1a type veth peer name veth1b
ip link add veth2a type veth peer name veth2b

# Move one end of each pair into the namespaces
ip link set veth1a netns ns_sender
ip link set veth2a netns ns_receiver

# Configure interfaces in default namespace (relay will use these)
ip addr add 10.0.1.254/24 broadcast 10.0.1.255 dev veth1b
ip addr add 10.0.2.254/24 broadcast 10.0.2.255 dev veth2b
ip link set veth1b up
ip link set veth2b up

# Configure ns_sender namespace
ip -n ns_sender addr add 10.0.1.1/24 broadcast 10.0.1.255 dev veth1a
ip -n ns_sender link set veth1a up
ip -n ns_sender link set lo up
# Define a route to the other network so that reverse path filtering is happy
ip -n ns_sender route add 10.0.2.0/24 via 10.0.1.254 dev veth1a

# Configure ns_receiver namespace  
ip -n ns_receiver addr add 10.0.2.1/24 broadcast 10.0.2.255 dev veth2a
ip -n ns_receiver link set veth2a up
ip -n ns_receiver link set lo up
# Define a route to the other network so that reverse path filtering is happy
ip -n ns_receiver route add 10.0.1.0/24 via 10.0.2.254 dev veth2a

echo "Network namespaces configured successfully"
echo "  ns_sender:   veth1a = 10.0.1.1/24"
echo "  ns_receiver: veth2a = 10.0.2.1/24"
echo "  default ns:  veth1b = 10.0.1.254/24, veth2b = 10.0.2.254/24"
