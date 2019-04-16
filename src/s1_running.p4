/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_UDP = 17;

const bit<32> HH_THRESHOLD = 5;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<32>  minRegVal;
    bit<32>  regVals1;
    bit<32>  regVals2;
    bit<32>  regVals3;
    bit<32> hashed_address_s1;
    bit<32> hashed_address_s2;
    bit<32> hashed_address_s3;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
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
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table forward_port {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 8;
        default_action = drop();
    }
    
    table dummy {
        key = {
            meta.hashed_address_s1: exact;
            meta.hashed_address_s2: exact;
            meta.hashed_address_s3: exact;
            meta.regVals1: exact;
            meta.regVals2: exact;
            meta.regVals3: exact;
            meta.minRegVal: exact;
        }
        actions = {
            NoAction;
        }
        size = 8;
        default_action = NoAction;
    }
    
    register<bit<32>>(1024) regCountMinSketch;
    bit<32> tmp;

    action compute_tcp_reg_index() {
        hash(meta.hashed_address_s1, HashAlgorithm.crc16, 10w0,
                 {
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.ipv4.protocol,
                    hdr.tcp.srcPort,
                    hdr.tcp.dstPort
                },
                20w1023);

        hash(meta.hashed_address_s2, HashAlgorithm.crc16, 10w0,
                 {
                    5w3,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.ipv4.protocol,
                    3w5,
                    hdr.tcp.srcPort,
                    hdr.tcp.dstPort
                },
                20w1023);

        hash(meta.hashed_address_s3, HashAlgorithm.crc16, 10w0,
                 {
                    7w11,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.ipv4.protocol,
                    8w9,
                    hdr.tcp.srcPort,
                    hdr.tcp.dstPort
                },
                20w1023);
    }

    action compute_udp_reg_index() {
        hash(meta.hashed_address_s1, HashAlgorithm.crc16, 10w0,
                 {
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.ipv4.protocol,
                    hdr.udp.srcPort,
                    hdr.udp.dstPort
                },
                20w1023);

        hash(meta.hashed_address_s2, HashAlgorithm.crc16, 10w0,
                 {
                    5w3,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.ipv4.protocol,
                    3w5,
                    hdr.udp.srcPort,
                    hdr.udp.dstPort
                },
                20w1023);

        hash(meta.hashed_address_s3, HashAlgorithm.crc16, 10w0,
                 {
                    7w11,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.ipv4.protocol,
                    8w9,
                    hdr.udp.srcPort,
                    hdr.udp.dstPort
                },
                20w1023);
    }

    action compute_ipv4_reg_index() {
        hash(meta.hashed_address_s1, HashAlgorithm.crc16, 10w0,
                 {hdr.ipv4.srcAddr, 7w11, hdr.ipv4.dstAddr}, 20w1023);

        hash(meta.hashed_address_s2, HashAlgorithm.crc16, 10w0,
                 {3w5, hdr.ipv4.srcAddr, 5w3, hdr.ipv4.dstAddr}, 20w1023);

        hash(meta.hashed_address_s3, HashAlgorithm.crc16, 10w0,
                 {2w0, hdr.ipv4.dstAddr, 1w1, hdr.ipv4.srcAddr}, 20w1023);
    }


    action update_register() {
        @atomic {
            regCountMinSketch.read(tmp, meta.hashed_address_s1);
            tmp = tmp + 1;
            regCountMinSketch.write(meta.hashed_address_s1, tmp);
            meta.regVals1 = tmp;
        }

        @atomic {
            regCountMinSketch.read(tmp, meta.hashed_address_s2);
            tmp = tmp + 1;
            regCountMinSketch.write(meta.hashed_address_s2, tmp);
            meta.regVals2 = tmp;
        }

        @atomic {
            regCountMinSketch.read(tmp, meta.hashed_address_s3);
            tmp = tmp + 1;
            regCountMinSketch.write(meta.hashed_address_s3, tmp);
            meta.regVals3 = tmp;
        }

        if (meta.regVals1 <  meta.regVals2) {
            meta.minRegVal = meta.regVals1;
        } else {
            meta.minRegVal = meta.regVals2;
        }

        if (meta.regVals3 <  meta.minRegVal) {
            meta.minRegVal = meta.regVals3;
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
        
            if (hdr.tcp.isValid()) {
                compute_tcp_reg_index();
            } else if (hdr.udp.isValid()) {
                compute_udp_reg_index();
            } else {
                compute_ipv4_reg_index();
            }

            update_register();

            dummy.apply();

            if (meta.minRegVal > HH_THRESHOLD) {
                drop();
            } else {
                forward_port.apply();
            }
        

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
               hdr.ipv4.version,
               hdr.ipv4.ihl,
               hdr.ipv4.diffserv,
               hdr.ipv4.totalLen,
               hdr.ipv4.identification,
               hdr.ipv4.flags,
               hdr.ipv4.fragOffset,
               hdr.ipv4.ttl,
               hdr.ipv4.protocol,
               hdr.ipv4.srcAddr,
               hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;