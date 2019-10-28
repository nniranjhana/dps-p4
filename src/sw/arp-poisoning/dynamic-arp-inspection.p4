#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_ARP = 0x0806;

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

header arp_t {
	bit<16> htype;
	bit<16> ptype;
	bit<8> hlen;
	bit<8> plen;
	bit<16> oper;
	macAddr_t SHA;
	ip4Addr_t SPA;
	macAddr_t THA;
	ip4Addr_t TPA;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t ethernet;
    arp_t arp;
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
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
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
    }

    action pkt_check(macAddr_t SHA, macAddr_t dstAddr, egressSpec_t port) {
        if (hdr.arp.SHA == SHA) {
            standard_metadata.egress_spec = port;
            hdr.ethernet.dstAddr = dstAddr;
        }
    }

    table arp_bcast {
        key = {
            hdr.ethernet.srcAddr: lpm;
        }
        actions = {
            pkt_fwd;
            drop;
            NoAction;
        }
    }

    table arp_cache {
        key = {
            hdr.arp.SPA: lpm;
            // Allow packet only for correct MAC-IP binding in the ARP cache
        }
        actions = {
            pkt_check;
            drop;
            NoAction;
        }
    }

    apply {
        if (hdr.arp.isValid()) {
            if (hdr.arp.oper == 1) {
                // If it is an ARP request message, send a broadcast
                arp_bcast.apply();
            }
            if (hdr.arp.oper == 2) {
                // If it is an ARP response packet, refer the ARP cache table
                arp_cache.apply();
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
    apply { }
}

/**********************************************************
******************** D E P A R S E R **********************
**********************************************************/

control DeparsePacket(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
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