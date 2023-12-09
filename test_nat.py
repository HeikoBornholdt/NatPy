#!/usr/bin/env python3
#
# Copyright (c) 2023 Heiko Bornholdt
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
# OR OTHER DEALINGS IN THE SOFTWARE.
#

import unittest
from unittest.mock import MagicMock
from nat import *

class NatTableTestCase(unittest.TestCase):
    def test_equality(self):
        entry1 = NatEntry(Protocol.ICMP, '192.168.1.100', None, '10.0.0.4', None, '10.0.0.1', None)
        entry2 = NatEntry(Protocol.ICMP, '192.168.1.100', None, '10.0.0.4', None, '10.0.0.1', None)

        self.assertEqual(entry1, entry2)
        self.assertEqual(entry1.__hash__(), entry2.__hash__())

class NatEntryTestCase(unittest.TestCase):
    def test_equality(self):
        entry1 = NatEntry(Protocol.ICMP, '192.168.1.100', None, '10.0.0.4', None, '10.0.0.1', None)
        entry2 = NatEntry(Protocol.ICMP, '192.168.1.100', None, '10.0.0.4', None, '10.0.0.1', None)

        self.assertEqual(entry1, entry2)
        self.assertEqual(entry1.__hash__(), entry2.__hash__())

class MappingPolicyTestCase(unittest.TestCase):
    # endpoint independent
    def test_map_endpoint_independent_same_host_same_port(self):
        nat = NatTable(wan_address='10.0.0.4',
                       mapping_policy=MappingPolicy.ENDPOINT_INDEPENDENT)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        self.assertEqual(1, len(nat.entries))

    def test_map_endpoint_independent_same_host_different_port(self):
        nat = NatTable(wan_address='10.0.0.4',
                       mapping_policy=MappingPolicy.ENDPOINT_INDEPENDENT)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        # packet to 10.0.0.1:52402
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52402
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        self.assertEqual(2, len(nat.entries))
        self.assertEqual(52401, list(nat.entries)[0].wan_port)
        self.assertEqual(52401, list(nat.entries)[1].wan_port)

    def test_map_endpoint_independent_different_host(self):
        nat = NatTable(wan_address='10.0.0.4',
                       mapping_policy=MappingPolicy.ENDPOINT_INDEPENDENT)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        # packet to 10.0.0.2:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.2'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        self.assertEqual(2, len(nat.entries))
        self.assertEqual(52401, list(nat.entries)[0].wan_port)
        self.assertEqual(52401, list(nat.entries)[1].wan_port)

    # host dependent
    def test_map_host_dependent_same_host_same_port(self):
        nat = NatTable(wan_address='10.0.0.4',
                       mapping_policy=MappingPolicy.HOST_DEPENDENT)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        self.assertEqual(1, len(nat.entries))

    def test_map_host_dependent_same_host_different_port(self):
        nat = NatTable(wan_address='10.0.0.4',
                       mapping_policy=MappingPolicy.HOST_DEPENDENT)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        # packet to 10.0.0.1:52402
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52402
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        self.assertEqual(2, len(nat.entries))
        self.assertEqual(52401, list(nat.entries)[0].wan_port)
        self.assertEqual(52401, list(nat.entries)[1].wan_port)

    def test_map_host_dependent_different_host(self):
        nat = NatTable(wan_address='10.0.0.4',
                       mapping_policy=MappingPolicy.HOST_DEPENDENT)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        # packet to 10.0.0.2:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.2'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        self.assertEqual(2, len(nat.entries))
        self.assertTrue(any(entry.wan_port == 52401 for entry in list(nat.entries)[:2]))
        self.assertNotEqual(list(nat.entries)[0].wan_port, list(nat.entries)[1].wan_port)

    # port dependent
    def test_map_port_dependent_same_host_same_port(self):
        nat = NatTable(wan_address='10.0.0.4',
                       mapping_policy=MappingPolicy.PORT_DEPENDENT)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        self.assertEqual(1, len(nat.entries))

    def test_map_port_dependent_same_host_different_port(self):
        nat = NatTable(wan_address='10.0.0.4',
                       mapping_policy=MappingPolicy.PORT_DEPENDENT)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        # packet to 10.0.0.1:52402
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52402
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        self.assertEqual(2, len(nat.entries))
        self.assertTrue(any(entry.wan_port == 52401 for entry in list(nat.entries)[:2]))
        self.assertNotEqual(list(nat.entries)[0].wan_port, list(nat.entries)[1].wan_port)

    def test_map_port_dependent_different_host(self):
        nat = NatTable(wan_address='10.0.0.4',
                       mapping_policy=MappingPolicy.PORT_DEPENDENT)

        # packet to 10.0.0.1:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.1'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        # packet to 10.0.0.2:52401
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '192.168.1.1'
        ipPacketIp.dst = '10.0.0.2'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.mapping_policy.map(packet, ipPacket, nat)

        self.assertEqual(2, len(nat.entries))
        self.assertTrue(any(entry.wan_port == 52401 for entry in list(nat.entries)[:2]))
        self.assertNotEqual(list(nat.entries)[0].wan_port, list(nat.entries)[1].wan_port)

class PortAllocationTestCase(unittest.TestCase):
    # port preservation
    def test_allocate_port_preservation_free(self):
        policy = AllocationPolicy.PORT_PRESERVATION

        ipPacket = MagicMock()
        ipPacketIp = MagicMock()
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)
        nat = MagicMock()
        nat.allocated_wan_ports = {}

        self.assertEqual(52401, policy.allocate(ipPacket, nat))

    def test_allocate_port_preservation_used(self):
        policy = AllocationPolicy.PORT_PRESERVATION

        ipPacket = MagicMock()
        ipPacketIp = MagicMock()
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)
        nat = MagicMock()
        nat.allocated_wan_ports = { 52401 }

        self.assertNotEqual(52401, policy.allocate(ipPacket, nat))

    # port contiguity
    def test_allocate_port_contiguity_free(self):
        policy = AllocationPolicy.PORT_CONTIGUITY

        ipPacket = MagicMock()
        ipPacketIp = MagicMock()
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)
        nat = MagicMock()
        nat.last_allocation = 65533
        nat.allocated_wan_ports = {}

        self.assertEqual(65534, policy.allocate(ipPacket, nat))
        self.assertEqual(65535, policy.allocate(ipPacket, nat))
        self.assertEqual(1024, policy.allocate(ipPacket, nat))

    def test_allocate_port_contiguity_used(self):
        policy = AllocationPolicy.PORT_CONTIGUITY

        ipPacket = MagicMock()
        ipPacketIp = MagicMock()
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)
        nat = MagicMock()
        nat.last_allocation = 65533
        nat.allocated_wan_ports = { 65535 }

        self.assertEqual(65534, policy.allocate(ipPacket, nat))
        self.assertEqual(1024, policy.allocate(ipPacket, nat))

    # random
    def test_allocate_random(self):
        policy = AllocationPolicy.RANDOM

        ipPacket = MagicMock()
        ipPacketIp = MagicMock()
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 52401
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)
        nat = MagicMock()
        nat.last_allocation = 65533
        nat.allocated_wan_ports = { }

        self.assertNotEqual(policy.allocate(ipPacket, nat), policy.allocate(ipPacket, nat))

class FilteringPolicyTestCase(unittest.TestCase):
    # endpoint independent
    def test_filter_endpoint_independent(self):
        nat = NatTable(wan_address='10.0.0.4',
                       filtering_policy=FilteringPolicy.ENDPOINT_INDEPENDENT)

        nat.entries.add(NatEntry(Protocol.TCP, '192.168.1.1', 52401, '10.0.0.4', 52401, '10.0.0.1', 10000, None))

        # packet from different port
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '10.0.0.1'
        ipPacketIp.dst = '10.0.0.4'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 10001
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.filtering_policy.filter(packet, ipPacket, nat)

        packet.accept.assert_called()

        # packet from different host
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '10.0.0.2'
        ipPacketIp.dst = '10.0.0.4'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 10001
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.filtering_policy.filter(packet, ipPacket, nat)

        packet.accept.assert_called()

    # host dependent
    def test_filter_host_dependent(self):
        nat = NatTable(wan_address='10.0.0.4',
                       filtering_policy=FilteringPolicy.HOST_DEPENDENT)

        nat.entries.add(NatEntry(Protocol.TCP, '192.168.1.1', 52401, '10.0.0.4', 52401, '10.0.0.1', 10000, None))

        # packet from different port
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '10.0.0.1'
        ipPacketIp.dst = '10.0.0.4'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 10001
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.filtering_policy.filter(packet, ipPacket, nat)

        packet.accept.assert_called()

        # packet from different host
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '10.0.0.2'
        ipPacketIp.dst = '10.0.0.4'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 10001
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.filtering_policy.filter(packet, ipPacket, nat)

        packet.drop.assert_called()

    # port dependent
    def test_filter_port_dependent(self):
        nat = NatTable(wan_address='10.0.0.4',
                       filtering_policy=FilteringPolicy.PORT_DEPENDENT)

        nat.entries.add(NatEntry(Protocol.TCP, '192.168.1.1', 52401, '10.0.0.4', 52401, '10.0.0.1', 10000, None))

        # packet from different port
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '10.0.0.1'
        ipPacketIp.dst = '10.0.0.4'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 10001
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.filtering_policy.filter(packet, ipPacket, nat)

        packet.drop.assert_called()

        # packet from different host
        packet = MagicMock()
        ipPacket = MagicMock()
        ipPacket.haslayer.side_effect = lambda arg: arg == TCP
        ipPacketIp = MagicMock()
        ipPacketIp.src = '10.0.0.2'
        ipPacketIp.dst = '10.0.0.4'
        ipPacketIp.chksum = '0'
        ipPacketTcp = MagicMock()
        ipPacketTcp.sport = 10001
        ipPacketTcp.dport = 52401
        ipPacketTcp.chksum = '0'
        ipPacket.__getitem__.side_effect = lambda key: {
            IP: ipPacketIp,
            TCP: ipPacketTcp,
        }.get(key)

        nat.filtering_policy.filter(packet, ipPacket, nat)

        packet.drop.assert_called()

if __name__ == '__main__':
    unittest.main()
