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
import argparse
import ipaddress
import sys
import random
import logging
from enum import Enum

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import ICMP, IP, TCP, UDP


class MappingPolicy(Enum):
    ENDPOINT_INDEPENDENT = 0
    HOST_DEPENDENT = 1
    PORT_DEPENDENT = 2

    def map(self, packet, ipPacket, nat):
        if ipPacket.haslayer(ICMP):
            # ignore mapping policy: create new mapping for every ICMP query
            # ignore allocation policy: not applicable here
            entry = NatEntry(Protocol.ICMP, ipPacket[IP].src, None, nat.wan_address, None, ipPacket[IP].dst, None,
                             ipPacket[ICMP].id)
            logging.debug(
                f"nat.py: MappingPolicy: Created ICMP mapping for packet {ipPacket.summary()} with ICMP ID {ipPacket[ICMP].id}: {entry}")
            nat.entries.add(entry)

            # replace src with my WAN address
            ipPacket[IP].src = entry.wan_ip

            # we altered the packet, we need to update all checksums (by deleting them)
            del ipPacket[IP].chksum
            del ipPacket[ICMP].chksum
            packet.set_payload(bytes(ipPacket))

            packet.accept()

        elif ipPacket.haslayer(TCP):
            entry = None
            for e in nat.entries:
                if self.value == MappingPolicy.ENDPOINT_INDEPENDENT.value and e.protocol == Protocol.TCP and \
                        e.lan_ip == ipPacket[IP].src and e.lan_port == ipPacket[TCP].sport:
                    # port dependent -> always reuse
                    entry = e
                    break

                elif self.value == MappingPolicy.HOST_DEPENDENT.value and e.protocol == Protocol.TCP and \
                        e.lan_ip == ipPacket[IP].src and e.lan_port == ipPacket[TCP].sport and e.inet_ip == ipPacket[
                    IP].dst:
                    # port dependent -> reuse if inet host matches
                    entry = e
                    break

                elif self.value == MappingPolicy.PORT_DEPENDENT.value and e.protocol == Protocol.TCP and \
                        e.lan_ip == ipPacket[IP].src and e.lan_port == ipPacket[TCP].sport and e.inet_ip == ipPacket[
                    IP].dst and e.inet_port == ipPacket[TCP].dport:
                    # port dependent -> reuse if inet host and port matches
                    entry = e
                    break

            if entry:
                # reuse wan endpoint
                wan_address = nat.wan_address
                wan_port = entry.wan_port
                logging.debug(f"nat.py: MappingPolicy: Reuse wan endpoint: {wan_address}:{wan_port}")

            else:
                wan_address = nat.wan_address
                wan_port = nat.allocation_policy.allocate(ipPacket, nat)
                logging.debug(f"nat.py: MappingPolicy: Use new wan endpoint: {wan_address}:{wan_port}")

            entry = NatEntry(Protocol.TCP, ipPacket[IP].src, ipPacket[TCP].sport, wan_address, wan_port,
                             ipPacket[IP].dst, ipPacket[TCP].dport, None)
            logging.debug(f"nat.py: MappingPolicy: Created TCP mapping for packet {ipPacket.summary()}: {entry}")
            nat.entries.add(entry)

            # replace src with my WAN address
            ipPacket[IP].src = entry.wan_ip
            ipPacket[TCP].sport = entry.wan_port

            # we altered the packet, we need to update all checksums (by deleting them)
            del ipPacket[IP].chksum
            del ipPacket[TCP].chksum
            packet.set_payload(bytes(ipPacket))

            packet.accept()

        elif ipPacket.haslayer(UDP):
            entry = None
            for e in nat.entries:
                if self.value == MappingPolicy.ENDPOINT_INDEPENDENT.value and e.protocol == Protocol.UDP and \
                        e.lan_ip == ipPacket[IP].src and e.lan_port == ipPacket[UDP].sport:
                    # port dependent -> always reuse
                    entry = e
                    break

                elif self.value == MappingPolicy.HOST_DEPENDENT.value and e.protocol == Protocol.UDP and \
                        e.lan_ip == ipPacket[IP].src and e.lan_port == ipPacket[UDP].sport and e.inet_ip == ipPacket[
                    IP].dst:
                    # port dependent -> reuse if inet host matches
                    entry = e
                    break

                elif self.value == MappingPolicy.PORT_DEPENDENT.value and e.protocol == Protocol.UDP and \
                        e.lan_ip == ipPacket[IP].src and e.lan_port == ipPacket[UDP].sport and e.inet_ip == ipPacket[
                    IP].dst and e.inet_port == ipPacket[UDP].dport:
                    # port dependent -> reuse if inet host and port matches
                    entry = e
                    break

            if entry:
                # reuse wan endpoint
                wan_address = nat.wan_address
                wan_port = entry.wan_port
                logging.debug(f"nat.py: MappingPolicy: Reuse wan endpoint: {wan_address}:{wan_port}")

            else:
                wan_address = nat.wan_address
                wan_port = nat.allocation_policy.allocate(ipPacket, nat)
                logging.debug(f"nat.py: MappingPolicy: Use new wan endpoint: {wan_address}:{wan_port}")

            entry = NatEntry(Protocol.UDP, ipPacket[IP].src, ipPacket[UDP].sport, wan_address, wan_port,
                             ipPacket[IP].dst, ipPacket[UDP].dport, None)
            logging.debug(f"nat.py: MappingPolicy: Created UDP mapping for packet {ipPacket.summary()}: {entry}")
            nat.entries.add(entry)

            # replace src with my WAN address
            ipPacket[IP].src = entry.wan_ip
            ipPacket[UDP].sport = entry.wan_port

            # we altered the packet, we need to update all checksums (by deleting them)
            del ipPacket[IP].chksum
            del ipPacket[UDP].chksum
            packet.set_payload(bytes(ipPacket))

            packet.accept()

        else:
            logging.debug(
                f"nat.py: MappingPolicy: Got outbound packet {ipPacket.summary()} with unsupported protocol. Drop it!")
            packet.drop()

    @classmethod
    def find_by_name(cls, name):
        for member in cls:
            if member.name.lower() == name.lower():
                return member
        return None


class AllocationPolicy(Enum):
    PORT_PRESERVATION = 0
    PORT_CONTIGUITY = 1
    RANDOM = 2

    def allocate(self, ipPacket, nat):
        return self._my_allocate(ipPacket, nat, self.value)

    def _my_allocate(self, ipPacket, nat, policy):
        if policy == AllocationPolicy.PORT_PRESERVATION.value:
            # port preservation
            lan_port = ipPacket[TCP].sport if ipPacket.haslayer(TCP) else ipPacket[UDP].sport

            if lan_port in nat.allocated_wan_ports:
                # port already used, switch to port contiguity allocation
                return self._my_allocate(ipPacket, nat, AllocationPolicy.PORT_CONTIGUITY.value)

            else:
                return lan_port

        elif policy == AllocationPolicy.PORT_CONTIGUITY.value:
            # port contiguity
            if nat.last_allocation is None:
                # init with random port
                nat.last_allocation = random.randint(1024, 65535)

            nat.last_allocation = (nat.last_allocation + 1 - 1024) % 64512 + 1024

            if nat.last_allocation in nat.allocated_wan_ports:
                # port already used, try to use new port
                return self._my_allocate(ipPacket, nat, policy)

            else:
                return nat.last_allocation

        else:
            # random
            random_port = random.randint(1024, 65535)

            if random_port in nat.allocated_wan_ports:
                # port already used, try another random port
                return self._my_allocate(ipPacket, nat, policy)

            else:
                return random_port

    @classmethod
    def find_by_name(cls, name):
        for member in cls:
            if member.name.lower() == name.lower():
                return member
        return None


class FilteringPolicy(Enum):
    ENDPOINT_INDEPENDENT = 0
    HOST_DEPENDENT = 1
    PORT_DEPENDENT = 2

    def filter(self, packet, ipPacket, nat):
        if ipPacket.haslayer(ICMP):
            logging.debug(f"nat.py: FilteringPolicy Got inbound packet {ipPacket.summary()} with ICMP ID {ipPacket[ICMP].id}")

            # search for matching mapping
            entry = None
            for e in nat.entries:
                if self.value == FilteringPolicy.ENDPOINT_INDEPENDENT.value and e.protocol == Protocol.ICMP and e.discriminator == \
                        ipPacket[ICMP].id:
                    # endpoint independent
                    entry = e
                    break

                elif self.value == FilteringPolicy.HOST_DEPENDENT.value and e.protocol == Protocol.ICMP and ipPacket[
                    IP].dst == e.wan_ip:
                    # host independent
                    entry = e
                    break

                elif self.value == FilteringPolicy.PORT_DEPENDENT.value and e.protocol == Protocol.ICMP and ipPacket[
                    IP].dst == e.wan_ip:
                    # port independent
                    entry = e
                    break

            if entry:
                logging.debug(f"nat.py: FilteringPolicy Found matching mapping {entry}. Pass inbound packet to {entry.lan_ip}")

                # replace dst with corresponding LAN address
                ipPacket[IP].dst = entry.lan_ip

                # we altered the packet, we need to update all checksums (by deleting them)
                del ipPacket[IP].chksum
                del ipPacket[ICMP].chksum
                packet.set_payload(bytes(ipPacket))

                packet.accept()

                nat.entries.remove(entry)

            else:
                logging.debug(f"nat.py: FilteringPolicy Found no matching mapping. Drop inbound packet!")
                packet.drop()

        elif ipPacket.haslayer(TCP):
            logging.debug(f"nat.py: FilteringPolicy Got inbound packet {ipPacket.summary()}")

            # search for matching mapping
            entry = None
            for e in nat.entries:
                if self.value == FilteringPolicy.ENDPOINT_INDEPENDENT.value and e.protocol == Protocol.TCP and e.wan_ip == \
                        ipPacket[IP].dst and e.wan_port == ipPacket[TCP].dport:
                    # endpoint independent
                    entry = e
                    break

                elif self.value == FilteringPolicy.HOST_DEPENDENT.value and e.protocol == Protocol.TCP and e.wan_ip == \
                        ipPacket[IP].dst and e.wan_port == ipPacket[TCP].dport and e.inet_ip == ipPacket[IP].src:
                    # host independent
                    entry = e
                    break

                elif self.value == FilteringPolicy.PORT_DEPENDENT.value and e.protocol == Protocol.TCP and e.wan_ip == \
                        ipPacket[IP].dst and e.wan_port == ipPacket[TCP].dport and e.inet_ip == ipPacket[
                    IP].src and e.inet_port == ipPacket[TCP].sport:
                    # port independent
                    entry = e
                    break

            if entry:
                logging.debug(
                    f"nat.py: FilteringPolicy Found matching mapping {entry}. Pass inbound packet to {entry.lan_ip}:{entry.lan_port}")

                # replace dst with corresponding LAN address
                ipPacket[IP].dst = entry.lan_ip
                ipPacket[TCP].dport = entry.lan_port

                # we altered the packet, we need to update all checksums (by deleting them)
                del ipPacket[IP].chksum
                del ipPacket[TCP].chksum
                packet.set_payload(bytes(ipPacket))

                packet.accept()

            else:
                logging.debug(f"nat.py: FilteringPolicy Found no matching mapping. Drop inbound packet!")
                packet.drop()

        elif ipPacket.haslayer(UDP):
            logging.debug(f"nat.py: FilteringPolicy Got inbound packet {ipPacket.summary()}")

            # search for matching mapping
            entry = None
            for e in nat.entries:
                if self.value == FilteringPolicy.ENDPOINT_INDEPENDENT.value and e.protocol == Protocol.UDP and e.wan_ip == \
                        ipPacket[IP].dst and e.wan_port == ipPacket[UDP].dport:
                    # endpoint independent
                    entry = e
                    break

                elif self.value == FilteringPolicy.HOST_DEPENDENT.value and e.protocol == Protocol.UDP and e.wan_ip == \
                        ipPacket[IP].dst and e.wan_port == ipPacket[UDP].dport and e.inet_ip == ipPacket[IP].src:
                    # host independent
                    entry = e
                    break

                elif self.value == FilteringPolicy.PORT_DEPENDENT.value and e.protocol == Protocol.UDP and e.wan_ip == \
                        ipPacket[IP].dst and e.wan_port == ipPacket[UDP].dport and e.inet_ip == ipPacket[
                    IP].src and e.inet_port == ipPacket[UDP].sport:
                    # port independent
                    entry = e
                    break

            if entry:
                logging.debug(
                    f"nat.py: FilteringPolicy Found matching mapping {entry}. Pass inbound packet to {entry.lan_ip}:{entry.lan_port}")

                # replace dst with corresponding LAN address
                ipPacket[IP].dst = entry.lan_ip
                ipPacket[UDP].dport = entry.lan_port

                # we altered the packet, we need to update all checksums (by deleting them)
                del ipPacket[IP].chksum
                del ipPacket[UDP].chksum
                packet.set_payload(bytes(ipPacket))

                packet.accept()

            else:
                logging.debug(f"nat.py: FilteringPolicy Found no matching mapping. Drop inbound packet!")
                packet.drop()

        else:
            logging.debug(
                f"nat.py: FilteringPolicy Got inbound packet {ipPacket.summary()} with unsupported protocol. Drop inbound packet!")
            packet.drop()

    @classmethod
    def find_by_name(cls, name):
        for member in cls:
            if member.name.lower() == name.lower():
                return member
        return None


class NatEntry:
    def __init__(self, protocol, lan_ip, lan_port, wan_ip, wan_port, inet_ip, inet_port, discriminator=None):
        self._protocol = protocol
        self._lan_ip = lan_ip
        self._lan_port = lan_port
        self._wan_ip = wan_ip
        self._wan_port = wan_port
        self._inet_ip = inet_ip
        self._inet_port = inet_port
        self._discriminator = discriminator

    def __str__(self):
        if self.lan_port == None and self.wan_port == None:
            return f'NatEntry(lan: {self.protocol}: {self.lan_ip}; wan: {self.wan_ip}; inet: {self.inet_ip})'
        else:
            return f'NatEntry(lan: {self.protocol}: {self.lan_ip}:{self.lan_port}; wan: {self.wan_ip}:{self.wan_port}; inet: {self.inet_ip}:{self.inet_port})'

    def __eq__(self, other):
        if isinstance(other, NatEntry):
            return self.protocol == other.protocol and self.lan_ip == other.lan_ip and self.lan_port == other.lan_port and self.wan_ip == other.wan_ip and self.wan_port == other.wan_port and self.inet_ip == other.inet_ip and self.inet_port == other.inet_port and self.discriminator == other.discriminator
        return False

    def __hash__(self):
        return hash((
                    self.protocol, self.lan_ip, self.lan_port, self.wan_ip, self.wan_port, self.inet_ip, self.inet_port,
                    self.discriminator))

    @property
    def protocol(self):
        return self._protocol

    @property
    def lan_ip(self):
        return self._lan_ip

    @property
    def lan_port(self):
        return self._lan_port

    @property
    def wan_ip(self):
        return self._wan_ip

    @property
    def wan_port(self):
        return self._wan_port

    @property
    def inet_ip(self):
        return self._inet_ip

    @property
    def inet_port(self):
        return self._inet_port

    @property
    def discriminator(self):
        return self._discriminator


class NatTable:
    def __init__(self,
                 lan_subnet=None,
                 wan_address=None,
                 mapping_policy=MappingPolicy.ENDPOINT_INDEPENDENT,
                 allocation_policy=AllocationPolicy.PORT_PRESERVATION,
                 filtering_policy=FilteringPolicy.PORT_DEPENDENT):
        self._lan_subnet = lan_subnet
        self._wan_address = wan_address
        self._mapping_policy = mapping_policy
        self._allocation_policy = allocation_policy
        self._filtering_policy = filtering_policy
        self._entries = set()
        self._last_allocation = None

    @property
    def lan_subnet(self):
        return self._lan_subnet

    @property
    def wan_address(self):
        return self._wan_address

    @property
    def mapping_policy(self):
        return self._mapping_policy

    @property
    def allocation_policy(self):
        return self._allocation_policy

    @property
    def filtering_policy(self):
        return self._filtering_policy

    @property
    def entries(self):
        return self._entries

    @property
    def last_allocation(self):
        return self._last_allocation

    @last_allocation.setter
    def last_allocation(self, last_allocation):
        self._last_allocation = last_allocation

    @property
    def allocated_wan_ports(self):
        return {entry.wan_port for entry in self.entries}

    def process_outbound_packet(self, packet, ipPacket):
        self.mapping_policy.map(packet, ipPacket, self)

    def process_inbound_packet(self, packet, ipPacket):
        self.filtering_policy.filter(packet, ipPacket, self)

    def __str__(self):
        # Define the column headers
        headers = ["Protocol", "LAN IP", "L.Port", "WAN IP", "W.Port", "Inet IP", "I.Port", "Discriminator"]

        if len(self.entries) == 0:
            return ''

        # Calculate the maximum width for each attribute
        widths = [max(len(header), max(len(str(getattr(entry, attr, ""))) for entry in self.entries)) for attr, header
                  in
                  zip(["protocol", "lan_ip", "lan_port", "wan_ip", "wan_port", "inet_ip", "inet_port", "discriminator"],
                      headers)]

        # Create the table header
        table = f"| {' | '.join(header.ljust(width) for header, width in zip(headers, widths))} |"

        # Create the separator line
        separator = f"+{'+'.join(['-' * (width + 2) for width in widths])}+"

        table += f"\n{separator}"

        # Add each entry to the table
        for index, entry in enumerate(self.entries):
            if index != 0:
                # Add the closing separator line
                table += f"\n{separator}"

            row = f"| {' | '.join(str(getattr(entry, attr, '')).ljust(width) for attr, width in zip(['protocol', 'lan_ip', 'lan_port', 'wan_ip', 'wan_port', 'inet_ip', 'inet_port', 'discriminator'], widths))} |"
            table += f"\n{row}"

        return table


# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
class Protocol(Enum):
    ICMP = 1
    TCP = 6
    UDP = 17

    def __str__(self):
        return self.name


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(prog='nat.py',
                                     description='python-based network address translator with configurable mapping, allocation, and filtering behavior for Netfilter NFQUEUE',
                                     epilog='For more information, visit: https://github.com/HeikoBornholdt/NatPy')
    parser.add_argument('--mapping',
                        choices=[p.name.lower() for p in MappingPolicy],
                        default='endpoint_independent',
                        help='new mapping creation policy')
    parser.add_argument('--allocation',
                        choices=[p.name.lower() for p in AllocationPolicy],
                        default='port_preservation',
                        help='new mappings\'s port allocation policy')
    parser.add_argument('--filtering',
                        choices=[p.name.lower() for p in FilteringPolicy],
                        default='port_dependent',
                        help='inbound packet filtering policy')
    parser.add_argument('--lan-subnet',
                        type=str,
                        help='private IP address range (CIDR notation)')
    parser.add_argument('--wan-address',
                        type=str,
                        help='public IP address')
    parser.add_argument('--queue',
                        type=int,
                        default=0,
                        help='queue number for Netfilter')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Increase output verbosity'
                        )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    def is_ip_in_network(ip, netmask):
        net = ipaddress.ip_network(netmask)
        return ipaddress.ip_address(ip) in net


    nat = NatTable(lan_subnet=args.lan_subnet,
                   wan_address=args.wan_address,
                   mapping_policy=MappingPolicy.find_by_name(args.mapping),
                   allocation_policy=AllocationPolicy.find_by_name(args.allocation),
                   filtering_policy=FilteringPolicy.find_by_name(args.filtering))


    def process_packet(packet):
        global nat

        # Convert the raw packet to a Scapy packet
        ipPacket = IP(packet.get_payload())

        if is_ip_in_network(ipPacket[IP].src, args.lan_subnet) and ipPacket[IP].dst != args.wan_address:
            # LAN to WAN
            logging.debug(f"nat.py: LAN->WAN packet: {ipPacket.summary()}")
            nat.process_outbound_packet(packet, ipPacket)
            logging.debug("")

        elif ipPacket[IP].dst == args.wan_address:
            # WAN to LAN?
            logging.debug(f"nat.py: WAN->LAN packet: {ipPacket.summary()}")
            nat.process_inbound_packet(packet, ipPacket)
            logging.debug("")

        else:
            logging.debug(f"nat.py: Pass through packet that is not crossing WAN<->LAN boundaries: {ipPacket.summary()}")
            packet.accept()

        logging.debug(nat)
        sys.stdout.flush()


    nfqueue = NetfilterQueue()
    nfqueue.bind(args.queue, process_packet)

    try:
        logging.debug(f"nat.py: Started")
        nfqueue.run()
    except KeyboardInterrupt:
        logging.debug('')

    nfqueue.unbind()
