# NatPy: python-based network address translator with configurable mapping, allocation, and filtering behavior for Netfilter NFQUEUE

## Supported NAT Behaviors

Three different policies define the behavior of the network address translator.
These policies can be combined in any way:

### Mapping Policy

The mapping policy is triggered every time a packet is sent from a private endpoint behind the NAT to some external public port.
The role of a mapping policy is to decide whether a new rule will be added or an existing one will be reused.
There are three different behaviors:

* **Endpoint-Independent:** Use the same mapping for any public endpoint.
* **Host-Dependent:** Create new mapping if the public endpoint's IP address differs.
* **Port-Dependent:** Create a new mapping of the public endpoint's IP address or port differences.

### Allocation Policy

A new public endpoint is bound whenever a new rule is added.
This policy allocates a new port.
That is, the mapping policy decides when to bind a new port, and the allocation policy decides which port should be bound as follows:
* **Port-Preservation:** Allocate the same port for mapping as the private endpoint uses.
* **Port Contiguity:** Allocate random port between [1024, 65536) for first mapping. Allocate nächthöheren port für subsequenzt mappings.
* **Random:** Allocate random port between [1024, 65536).

### Filtering Policy

The filtering policy decides whether a packet from the outside world to a public endpoint of a NAT gateway should be forwarded to the corresponding private endpoint.
There are three filtering policies with the following conditions for allowing receiving:
* **Endpoint-Independent:** Every public endpoint is allowed.
* **Host-Dependent:** Every port of the same public endpoint is allowed.
* **Port-Dependent:** Only the same public endpoint is allowed.

### Popular Behaviors:

Here are examples of policies to choose to achieve common NAT type behaviors:

| **NAT type**    | **Mapping Policy**                | **Allocation Policy** | **Filtering Policy**   |
|-----------------|-----------------------------------|-----------------------|------------------------|
| Full-cone       | `endpoint_independent`            |                       | `endpoint_independent` |
| Restricted-Cone | `endpoint_independent`            |                       | `host_dependent`       |
| Port-Restricted | `endpoint_independent`            |                       | `port_dependent`       |
| Symmetric       | `host_dependent`/`port_dependent` | (`random`)            | `port_dependent`       |


## Installation

```bash
apt install build-essential python3-dev libnetfilter-queue-dev
pip install -r requirements.txt
```

## Example Usage

In this example, we assume your public WAN address is `93.184.216.34`, your private LAN subnet is `192.168.178.0/24`, and we want to direct packets to Netfilter queue `0`.
First, ensure your host has both WAN and LAN interfaces and IP forwarding is enabled (e.g., by run `sysctl net.ipv4.ip_forward=1`).
Then, you need to configure Netfilter to direct traffic to a Netfilter queue by running and starting NatPy.

```bash
# direct LAN -> WAN packets to queue
$ iptables --table filter \
	--append FORWARD \
	--jump NFQUEUE \
	--queue-num 0 \
	--source 192.168.178.0/24 \
	! --destination 93.184.216.34

# direct WAN -> LAN packets to queue
$ iptables --table mangle \
	--append PREROUTING \
	--jump NFQUEUE \
	--queue-num 0 \
	--destination 93.184.216.34

# start NatPy
$ ./nat.py --mapping port_dependent \
	--allocation random \
	--filtering port_dependent \
	--lan-subnet 192.168.178.0/24 \
	--wan-address 93.184.216.34 \
	--queue 0
```

## Help

```bash
$ ./nat.py --help
usage: nat.py [-h] [--mapping {endpoint_independent,host_dependent,port_dependent}] [--allocation {port_preservation,port_contiguity,random}] [--filtering {endpoint_independent,host_dependent,port_dependent}] [--lan-subnet LAN_SUBNET]
              [--wan-address WAN_ADDRESS] [--queue QUEUE]

options:
  -h, --help            show this help message and exit
  --mapping {endpoint_independent,host_dependent,port_dependent}
                        new mapping creation policy
  --allocation {port_preservation,port_contiguity,random}
                        new mappings's port allocation policy
  --filtering {endpoint_independent,host_dependent,port_dependent}
                        inbound packet filtering policy
  --lan-subnet LAN_SUBNET
                        private IP address range (CIDR notation)
  --wan-address WAN_ADDRESS
                        public IP address
  --queue QUEUE         queue number for Netfilter
```

## License

This is free software under the terms of the [MIT License](LICENSE).
