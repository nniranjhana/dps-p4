#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> UDP_PROTOCOL = 0x11;

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
    bit<16> checksum; /* optional */
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
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
        transition accept;
    }
}

/**********************************************************
******** C H E C K S U M   V E R I F I C A T I O N ********
**********************************************************/

control ChecksumVerify(inout headers hdr, inout metadata meta) {
    apply { }
}

/**********************************************************
*********** I N G R E S S   P R O C E S S I N G ***********
**********************************************************/

control IngressProcess(inout headers hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action pkt_fwd(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table estd_client {
        key = {
            hdr.ipv4.dstAddr: lpm;
            // Permit packet only if destination IP is in the DHCP bindings table
        }
        actions = {
            pkt_fwd;
            drop;
            NoAction;
        }
    }

    table nack_client {
        key = {
            hdr.ethernet.srcAddr: lpm;
        }
        actions = {
            drop;
            NoAction;
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
            // If client has already been assigned an IP address
            if (hdr.ipv4.srcAddr != 0) {
                estd_client.apply();
            }
            else {
                // Drop the non-DHCP packets till client IP is established
                if (!(hdr.udp.isValid() && ((hdr.udp.dstPort == 67) || (hdr.udp.dstPort == 68)))) {
                    nack_client.apply();
                }
                else estd_client.apply();
            }
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

control ChecksumCompute(inout headers hdr, inout metadata meta) {
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
ChecksumVerify(),
IngressProcess(),
EgressProcess(),
ChecksumCompute(),
DeparsePacket()
) main;
