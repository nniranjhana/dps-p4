//
// Copyright (c) 2017 Stephen Ibanez
// All rights reserved.
//
// This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
// under National Science Foundation under Grant No. CNS-0855268,
// the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
// by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
// as part of the DARPA MRC research programme.
//
// @NETFPGA_LICENSE_HEADER_START@
//
// Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
// license agreements.  See the NOTICE file distributed with this work for
// additional information regarding copyright ownership.  NetFPGA licenses this
// file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
// "License"); you may not use this file except in compliance with the
// License.  You may obtain a copy of the License at:
//
//   http://www.netfpga-cic.org
//
// Unless required by applicable law or agreed to in writing, Work distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations under the License.
//
// @NETFPGA_LICENSE_HEADER_END@
//


#include <core.p4>
#include <sume_switch.p4>

/*
 * IP Source Guard: 
 * P4 program to demonstrate an IP source guard to detect IP spoofing attacks.
 */

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> UDP_PROTOCOL = 0x11;

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// standard Ethernet header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

// IPv4 header without options
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
    bit<16> pChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// UDP header
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum; /* optional */
}

// List of all recognized headers
struct Parsed_packet {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
}

// user defined metadata: can be used to shared information between
// TopParser, TopPipe, and TopDeparser 
struct user_metadata_t {
    bit<8>  unused;
}

// digest data to be sent to CPU if desired. MUST be 256 bits!
struct digest_data_t {
    bit<256>  unused;
}

// Parser Implementation
@Xilinx_MaxPacketRegion(16384)
parser TopParser(packet_in b, 
                 out Parsed_packet p, 
                 out user_metadata_t user_metadata,
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata) {
    state start {
        b.extract(p.ethernet);
        user_metadata.unused = 0;
        digest_data.unused = 0;
        transition select(p.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        } 
    }

    state parse_ipv4 { 
        b.extract(p.ipv4);
        transition select(p.ipv4.protocol) {
            UDP_PROTOCOL: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        b.extract(p.udp);
        transition accept;
    }
}

// match-action pipeline
control TopPipe(inout Parsed_packet p,
                inout user_metadata_t user_metadata, 
                inout digest_data_t digest_data, 
                inout sume_metadata_t sume_metadata) {

    action pkt_fwd(port_t port) {
        sume_metadata.dst_port = port;
    }

    table estd_client {
        key = {
            p.ipv4.srcAddr: exact;
            // Permit packet only if source IP is in the DHCP bindings table
        }
        actions = {
            pkt_fwd;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    table nack_client {
        key = {
            p.ethernet.srcAddr: exact;
        }
        actions = {
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    table wait_client {
        key = {
            p.ethernet.srcAddr: exact;
        }
        actions = {
            pkt_fwd;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    apply {
        if (p.ipv4.isValid()) {
            // If client has already been assigned an IP address
            if (p.ipv4.srcAddr != 0) {
                estd_client.apply();
            }
            else {
                // Allow only DHCP packets without client IP
                if (p.udp.isValid() && p.udp.srcPort == 68) {
                    wait_client.apply();
                }
                // Drop the non-DHCP packets till client IP is established
                else nack_client.apply();
            }
        }
    }
}

// Deparser Implementation
@Xilinx_MaxPacketRegion(16384)
control TopDeparser(packet_out b,
                    in Parsed_packet p,
                    in user_metadata_t user_metadata,
                    inout digest_data_t digest_data, 
                    inout sume_metadata_t sume_metadata) { 
    apply {
        b.emit(p.ethernet); 
        b.emit(p.ipv4);
        b.emit(p.udp);
    }
}


// Instantiate the switch
SimpleSumeSwitch(TopParser(), TopPipe(), TopDeparser()) main;

