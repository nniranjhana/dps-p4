#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> UDP_PROTOCOL = 0x11;
const bit<8> DHCP_SERVER_PORT = 0x43 //67
const bit<8> DHCP_CLIENT_PORT = 0x44 //68

/**********************************************************
********************** H E A D E R S **********************
**********************************************************/

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
//    bit<16> checksum; /* optional */
}

header dhcp_t {
	bit<8> opCode;
	bit<8> hType;
	bit<8> hLen;
	bit<8> hops;
	bit<32> xid;
	bit<16> secs;
	bit<16> flags;
	ip4Addr_t CIAddr;
	ip4Addr_t YIAddr;
	ip4Addr_t SIAddr;
	ip4Addr_t GIAddr;
	bit<128> CHAddr;
	bit<512> sName;
	bit<1024> file;
	//bit<?> options;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    dhcp_t dhcp;
}

/**********************************************************
*********************** P A R S E R ***********************
**********************************************************/

parser ParsePacket(packet_in packet,
                   out headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            UDP_PROTOCOL: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.srcPort) {
            DHCP_SERVER_PORT: parse_dhcp;
            default: transition select(hdr.udp.dstPort) {
                DHCP_CLIENT_PORT: parse_dhcp;
                default: accept;
            }
        }
    }

    state parse_dhcp {
        packet.extract(hdr.dhcp);
        transition accept;
    }
}

/**********************************************************
******** C H E C K S U M   V E R I F I C A T I O N ********
**********************************************************/

control VerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/**********************************************************
*********** I N G R E S S   P R O C E S S I N G ***********
**********************************************************/

control IngressProcess(inout headers hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table dhcp_snoop_db {
        key = {
            hdr.ipv4.srcAddr: exact;
            // Ensure DHCP server request originates from inside the network
        }
        actions = {
            // Forward packet if exact match, else drop it
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid() && !hdr.udp.isValid()) {
            // Directly process the non-UDP packets
            ipv4_lpm.apply();
        }

        if (hdr.dhcp.isValid()) {
            if(hdr.dhcp.opCode == 2) {
                // Process DHCP messages from server
                dhcp_snoop_db.apply();
            }
            if (hdr.dhcp.opCode == 1) {
                // Process DHCP messages from client
                // TODO: How to match different bits?
                if (hdr.ethernet.srcAddr == hdr.dhcp.CHAddr) {
                    // Drop packets where source MAC and client HW addresses do not match
                    ipv4_lpm.apply();
                }
            }
        }
        else {
            // Process the remaining non-DHCP packets
            ipv4_lpm.apply();
        }
    }
}

/**********************************************************
************ E G R E S S   P R O C E S S I N G ************
**********************************************************/

control EgressProcess(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {
    apply { }
}

/**********************************************************
********* C H E C K S U M   C O M P U T A T I O N *********
**********************************************************/

control ComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/**********************************************************
******************** D E P A R S E R **********************
**********************************************************/

control DeparsePacket(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

/**********************************************************
*********************** S W I T C H ***********************
**********************************************************/

V1Switch(
ParsePacket(),
VerifyChecksum(),
IngressProcess(),
EgressProcess(),
ComputeChecksum(),
DeparsePacket()
) main;
