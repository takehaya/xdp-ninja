// IPv4 base header (options are not modelled; ihl >5 is left to codegen).
header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_length;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}

// Ethernet/VLAN/QinQ select ipv4 via the ethertype.
const bit<16> IPV4_ETH_ETHERTYPE  = 0x0800;
const bit<16> IPV4_VLAN_ETHERTYPE = 0x0800;
const bit<16> IPV4_QINQ_ETHERTYPE = 0x0800;

// SRv6 transports IPv4-in-IPv6 (SRv6 → IPv4 inner): the SRH
// next_header byte uses IANA protocol number 4 (IPIP).
const bit<8>  IPV4_SRV6_NEXT_HEADER = 4;

// Under GRE, the protocol_type field carries the EtherType of the
// payload — IPv4 uses the well-known 0x0800.
const bit<16> IPV4_GRE_PROTOCOL_TYPE = 0x0800;

// Self-validating parser: `transition select(hdr.version) { ... }`
// guarantees the first nibble is 4. When a parent layer has no Field
// dispatch (e.g. MPLS, GTP-U, VXLAN inner Ethernet), resolver allows
// the chain via DispatchSelfValidating and the runtime check happens
// here.
//
// The `skip_options` state walks past the IPv4 options trailer using
// the standard P4-16 `pkt.advance` form. Total header length is
// IHL × 4 bytes; subtract the 20-byte fixed minimum to obtain the
// options length. IHL < 5 underflows the `bit<32>` arithmetic, which
// codegen catches with an explicit lower-bound check before it can
// advance R4.
parser IPv4Fragment(packet_in pkt, out ipv4_h hdr) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version) {
            4:       skip_options;
            default: reject;
        }
    }
    state skip_options {
        pkt.advance(((bit<32>)(hdr.ihl - 5)) << 5);
        transition accept;
    }
}
