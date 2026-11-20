//! ZDP Header Compression (RFC 6.5 § 5.26)

use crate::classifier;
use crate::defs::FiveTuple;
use crate::prelude::*;
use bytes::Buf;
use ip4sum;
use zerocopy::*;
use zpr::packet_info::compression_mode::*;
use zpr_utils::net_defs;

const ZDP_V4_FRAG_INFO_PRESENT: u8 = 0b00001000;

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
struct CompressedIPv6Header {
    pub version_and_tc_upper: u8,
    pub tc_lower_and_fl_upper: u8,
    pub fl_lower: [u8; 2],
    pub hop_limit: u8,
}

fn compress_ipv4(
    compression_mode: CompressionMode,
    l4_protocol: net_defs::IpProtocol,
    pkt: &mut Packet,
) {
    let hdr = classifier::IPv4Header::ref_from_prefix(pkt.body())
        .unwrap()
        .0;
    let hl = hdr.vhl & classifier::IPV4_HEADER_LENGTH_MASK;
    let dscp = hdr.dscp;
    let frag_flags = hdr.frag_offset.get() >> 13; // fragmentation flags
    let frag_id = hdr.frag_id;
    let frag_offset = hdr.frag_offset & 0x1fff; // ignores fragmentation flags; NOTE/TODO: spec deviation
    let ttl = hdr.ttl;

    pkt.advance(std::mem::size_of::<classifier::IPv4Header>());

    compress_l4(compression_mode, l4_protocol, pkt);

    pkt.push_header(&ttl);

    let frag_info_present = frag_offset.get() != 0;
    if frag_info_present {
        pkt.push_header(&frag_offset);
    }

    pkt.push_header(&frag_id);

    let hl_zdpflags = (hl << 4)
        | (if frag_info_present {
            ZDP_V4_FRAG_INFO_PRESENT
        } else {
            0
        })
        | (frag_flags as u8);

    pkt.push_header(&[hl_zdpflags, dscp]);
}

fn expand_ipv4(
    compression_mode: CompressionMode,
    five_tuple: &FiveTuple,
    pkt: &mut Packet,
) -> Result<(), MalformedPacket> {
    let hl_zdpflags = pkt.try_get_u8()?;
    let tos = pkt.try_get_u8()?;

    let hl = hl_zdpflags >> 4;
    let frag_info_present = (hl_zdpflags & ZDP_V4_FRAG_INFO_PRESENT) != 0;
    let frag_flags = hl_zdpflags & 0x07;

    let frag_id = pkt.try_get_u16()?.to_be_bytes();

    let mut frag_offset;
    if frag_info_present {
        frag_offset = pkt.try_get_u16()?;
    } else {
        frag_offset = 0u16;
    }
    frag_offset |= (frag_flags as u16) << 13; // NOTE/TODO: spec deviation

    let ttl = pkt.try_get_u8()?;

    expand_l4(compression_mode, five_tuple, pkt)?;

    let body_len = pkt.body().len();

    let hdr = pkt.alloc_zeroed_header::<classifier::IPv4Header>();
    hdr.vhl = (4 << 4) | hl;
    hdr.dscp = tos;
    hdr.total_length = ((body_len + std::mem::size_of::<classifier::IPv4Header>()) as u16).into();
    hdr.frag_id = frag_id;
    hdr.frag_offset = frag_offset.into();
    hdr.ttl = ttl;
    hdr.proto = five_tuple.l4_protocol;
    hdr.src_address = five_tuple.src_address.read_as_v4();
    hdr.dst_address = five_tuple.dst_address.read_as_v4();

    // The header length comes from the peer; the checksum is computed over
    // that many bytes, so it must cover a whole IPv4 header and no more
    // than the expanded packet.
    let header_len = (hl as usize) << 2;
    if header_len < std::mem::size_of::<classifier::IPv4Header>() || header_len > pkt.body().len() {
        return Err(MalformedPacket);
    }
    let csum = ip4sum::checksum(&pkt.body()[..header_len]).to_be_bytes();
    classifier::IPv4Header::mut_from_prefix(pkt.body_mut())?
        .0
        .header_checksum = csum;
    Ok(())
}

fn compress_ipv6(
    compression_mode: CompressionMode,
    l4_protocol: net_defs::IpProtocol,
    pkt: &mut Packet,
) {
    let hdr = classifier::IPv6Header::ref_from_prefix(pkt.body())
        .unwrap()
        .0;
    let version_and_tc_upper = hdr.version_and_tc_upper;
    let tc_lower_and_fl_upper = hdr.tc_lower_and_fl_upper;
    let fl_lower = hdr.fl_lower;
    let hop_limit = hdr.hop_limit;

    pkt.advance(std::mem::size_of::<classifier::IPv6Header>());

    compress_l4(compression_mode, l4_protocol, pkt);

    let chdr = pkt.alloc_zeroed_header::<CompressedIPv6Header>();
    chdr.version_and_tc_upper = version_and_tc_upper;
    chdr.tc_lower_and_fl_upper = tc_lower_and_fl_upper;
    chdr.fl_lower = fl_lower;
    chdr.hop_limit = hop_limit;
}

fn expand_ipv6(
    compression_mode: CompressionMode,
    five_tuple: &FiveTuple,
    pkt: &mut Packet,
) -> Result<(), MalformedPacket> {
    let chdr = CompressedIPv6Header::ref_from_prefix(pkt.body())?.0;
    let version_and_tc_upper = chdr.version_and_tc_upper;
    let tc_lower_and_fl_upper = chdr.tc_lower_and_fl_upper;
    let fl_lower = chdr.fl_lower;
    let hop_limit = chdr.hop_limit;

    pkt.advance(std::mem::size_of::<CompressedIPv6Header>());

    expand_l4(compression_mode, five_tuple, pkt)?;

    let body_len = pkt.body().len();

    let hdr = pkt.alloc_zeroed_header::<classifier::IPv6Header>();
    hdr.version_and_tc_upper = version_and_tc_upper;
    hdr.tc_lower_and_fl_upper = tc_lower_and_fl_upper;
    hdr.fl_lower = fl_lower;
    hdr.payload_length = (body_len as u16).into(); // NOTE: we do not allow jumbo payloads
    hdr.next_header = five_tuple.l4_protocol;
    hdr.hop_limit = hop_limit;
    hdr.src_address = five_tuple.src_address;
    hdr.dst_address = five_tuple.dst_address;
    Ok(())
}

fn compress_l4(
    compression_mode: CompressionMode,
    l4_protocol: net_defs::IpProtocol,
    pkt: &mut Packet,
) {
    match l4_protocol {
        net_defs::ip_number::TCP => compress_tcp(compression_mode, pkt),
        net_defs::ip_number::UDP => compress_udp(compression_mode, pkt),
        _ => (), // no compression defined for other protocols
    }
}

fn expand_l4(
    compression_mode: CompressionMode,
    five_tuple: &FiveTuple,
    pkt: &mut Packet,
) -> Result<(), MalformedPacket> {
    // NOTE: "PRESENT" CompressionMode bits indicate that the corresponding field
    // is present _in the traffic classifier_, which means it should be _absent_
    // in the compressed packet.  (Hence the checks herein look as if they are backward.)

    match five_tuple.l4_protocol {
        net_defs::ip_number::TCP => expand_tcp(compression_mode, five_tuple, pkt),
        net_defs::ip_number::UDP => expand_udp(compression_mode, five_tuple, pkt),
        _ => Ok(()), // no compression defined for other protocols
    }
}

fn compress_tcp(compression_mode: CompressionMode, pkt: &mut Packet) {
    let src_port = pkt.get_u16();
    let dst_port = pkt.get_u16();

    // remove checksum
    // NOTE: we expect classifier to have filtered out packets
    // with incorrect checksums
    pkt.body_mut().copy_within(
        ..(std::mem::offset_of!(classifier::TCPHeader, checksum) - 4),
        2,
    );
    pkt.advance(2);

    if compression_mode & DESTINATION_PORT_PRESENT == 0 {
        pkt.push_u16(dst_port);
    }

    if compression_mode & SOURCE_PORT_PRESENT == 0 {
        pkt.push_u16(src_port);
    }
}

fn expand_tcp(
    compression_mode: CompressionMode,
    five_tuple: &FiveTuple,
    pkt: &mut Packet,
) -> Result<(), MalformedPacket> {
    let src_port = if compression_mode & SOURCE_PORT_PRESENT != 0 {
        five_tuple.src_port
    } else {
        pkt.try_get_u16()?
    };

    let dst_port = if compression_mode & DESTINATION_PORT_PRESENT != 0 {
        five_tuple.dst_port
    } else {
        pkt.try_get_u16()?
    };

    // The rest of the TCP header must be present: everything but the
    // ports, read above, and the checksum, which compression removed.
    let rest_of_header_len = std::mem::size_of::<classifier::TCPHeader>() - 4 - 2;
    if pkt.body().len() < rest_of_header_len {
        return Err(MalformedPacket);
    }

    // make space for checksum
    pkt.alloc_zeroed_headroom(2);
    pkt.body_mut().copy_within(
        2..(2 + std::mem::offset_of!(classifier::TCPHeader, checksum) - 4),
        0,
    );

    pkt.push_u16(dst_port);
    pkt.push_u16(src_port);

    // zero out checksum for computation
    classifier::TCPHeader::mut_from_prefix(pkt.body_mut())?
        .0
        .checksum = [0u8; 2];

    // recompute checksum
    let csum = net_defs::inet_l4_checksum(
        five_tuple.l3_type.0,
        &five_tuple.src_address,
        &five_tuple.dst_address,
        net_defs::ip_number::TCP,
        pkt.body(),
    );
    classifier::TCPHeader::mut_from_prefix(pkt.body_mut())?
        .0
        .checksum = csum;
    Ok(())
}

fn compress_udp(compression_mode: CompressionMode, pkt: &mut Packet) {
    let src_port = pkt.get_u16();
    let dst_port = pkt.get_u16();

    // remove length
    // NOTE: we do not support v6 jumbograms (whose length field is 0);
    // the classifier should filter these out (as it does
    // UDPs packet whose length is incorrect)
    pkt.advance(2);

    // leave checksum

    if compression_mode & DESTINATION_PORT_PRESENT == 0 {
        pkt.push_u16(dst_port);
    }

    if compression_mode & SOURCE_PORT_PRESENT == 0 {
        pkt.push_u16(src_port);
    }
}

fn expand_udp(
    compression_mode: CompressionMode,
    five_tuple: &FiveTuple,
    pkt: &mut Packet,
) -> Result<(), MalformedPacket> {
    let src_port = if compression_mode & SOURCE_PORT_PRESENT != 0 {
        five_tuple.src_port
    } else {
        pkt.try_get_u16()?
    };

    let dst_port = if compression_mode & DESTINATION_PORT_PRESENT != 0 {
        five_tuple.dst_port
    } else {
        pkt.try_get_u16()?
    };

    // leave checksum in place

    // - 2 accounts for the checksum, which must be present
    let payload_len = pkt.body().len().checked_sub(2).ok_or(MalformedPacket)?;

    pkt.push_u16((payload_len + std::mem::size_of::<classifier::UDPHeader>()) as u16);
    pkt.push_u16(dst_port);
    pkt.push_u16(src_port);
    Ok(())
}

/// Compress a packet.  Does not inspect payload length, so trailers (e.g. A2A MAC) may be present.
pub fn compress(
    compression_mode: CompressionMode,
    l3_type: L3Type,
    l4_protocol: net_defs::IpProtocol,
    pkt: &mut Packet,
) {
    match l3_type {
        L3Type::Ipv4 => compress_ipv4(compression_mode, l4_protocol, pkt),
        L3Type::Ipv6 => compress_ipv6(compression_mode, l4_protocol, pkt),
        _ => (), // no compression defined for non-IP packets
    }
}

/// A compressed packet that cannot be expanded: it is too short for the
/// headers its classifier says it carries, or a header field is invalid.
#[derive(Debug, PartialEq, Eq)]
pub struct MalformedPacket;

/// A read past the end of the packet.
impl From<bytes::TryGetError> for MalformedPacket {
    fn from(_: bytes::TryGetError) -> Self {
        MalformedPacket
    }
}

/// A header that does not fit in what is left of the packet.
impl<A, S, V> From<ConvertError<A, S, V>> for MalformedPacket {
    fn from(_: ConvertError<A, S, V>) -> Self {
        MalformedPacket
    }
}

/// Expand a packet.  Fills payload length from body length, so trailers (e.g. A2A MAC) must not be present.
///
/// The packet comes from a peer, so every read is bounds-checked: a body too
/// short for the headers `five_tuple` says it carries, or with an invalid
/// IPv4 header length, is refused with [MalformedPacket], and the caller
/// drops it. On error the packet's contents are unspecified.
pub fn expand(
    compression_mode: CompressionMode,
    five_tuple: &FiveTuple,
    pkt: &mut Packet,
) -> Result<(), MalformedPacket> {
    match five_tuple.l3_type {
        L3Type::Ipv4 => expand_ipv4(compression_mode, five_tuple, pkt),
        L3Type::Ipv6 => expand_ipv6(compression_mode, five_tuple, pkt),
        _ => Ok(()), // no compression defined for non-IP packets
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::classifier;
    use crate::config;
    use crate::packet::Packet;
    use bytes::BufMut;

    #[test]
    fn test_round_trip() {
        for &(desc, body) in TEST_CASES {
            let buf = Box::new([0u8; config::PACKET_BUFFER_SIZE]);
            let mut pkt = Packet::new(buf, 256);
            pkt.put(body);

            let (metadata, pkt_body) = pkt.metadata_mut_and_body_mut();
            let cls_res = match classifier::classify(metadata.five_tuple_mut(), pkt_body) {
                Ok(cls_res) => cls_res,
                Err(err) => panic!("{desc}: classify() failed: {err:?}"),
            };
            assert!(
                cls_res == classifier::ClassifierResult::OK
                    || cls_res == classifier::ClassifierResult::UnclassifiedL4
            );
            let ft = *pkt.metadata().five_tuple();

            for compression_mode in [
                CompressionMode::default(),
                SOURCE_PORT_PRESENT,
                DESTINATION_PORT_PRESENT,
                SOURCE_PORT_PRESENT | DESTINATION_PORT_PRESENT,
            ] {
                compress(compression_mode, ft.l3_type, ft.l4_protocol, &mut pkt);
                expand(compression_mode, &ft, &mut pkt).unwrap();
                assert_eq!(
                    pkt.body(),
                    body,
                    "{desc}; compression mode 0x{compression_mode:02x}",
                );
            }
        }
    }

    /// A packet holding `body`, with the headroom a received packet has.
    fn packet_of(body: &[u8]) -> Packet {
        let buf = Box::new([0u8; config::PACKET_BUFFER_SIZE]);
        let mut pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
        pkt.put(body);
        pkt
    }

    /// zl-zipline#283: `expand` reads only what the packet holds. Every
    /// test case is compressed, then cut short at each length inside its
    /// compressed IP and TCP/UDP headers; each cut is refused with an
    /// error, never a panic. The body comes from a peer, and the
    /// classifier it is expanded with may belong to another flow (a reused
    /// DLT id), so its length cannot be trusted. This covers truncated
    /// IPv4, IPv6, TCP and UDP headers, in every compression mode.
    #[test]
    fn test_expand_rejects_truncated_headers() {
        for &(desc, body) in TEST_CASES {
            let mut pkt = packet_of(body);
            let (metadata, pkt_body) = pkt.metadata_mut_and_body_mut();
            classifier::classify(metadata.five_tuple_mut(), pkt_body).unwrap();
            let ft = *pkt.metadata().five_tuple();

            // The uncompressed header lengths, so that what follows them
            // (TCP options and payload) is the part compression keeps as is.
            let ip_header_len = match ft.l3_type {
                L3Type::Ipv4 => std::mem::size_of::<classifier::IPv4Header>(),
                _ => std::mem::size_of::<classifier::IPv6Header>(),
            };
            let l4_header_len = match ft.l4_protocol {
                net_defs::ip_number::TCP => std::mem::size_of::<classifier::TCPHeader>(),
                net_defs::ip_number::UDP => std::mem::size_of::<classifier::UDPHeader>(),
                _ => 0, // not compressed
            };
            let kept_len = body.len() - ip_header_len - l4_header_len;

            for compression_mode in [
                CompressionMode::default(),
                SOURCE_PORT_PRESENT,
                DESTINATION_PORT_PRESENT,
                SOURCE_PORT_PRESENT | DESTINATION_PORT_PRESENT,
            ] {
                let mut pkt = packet_of(body);
                compress(compression_mode, ft.l3_type, ft.l4_protocol, &mut pkt);
                let compressed = pkt.body().to_vec();
                let headers_len = compressed.len() - kept_len;

                for len in 0..headers_len {
                    let mut pkt = packet_of(&compressed[..len]);
                    assert_eq!(
                        expand(compression_mode, &ft, &mut pkt),
                        Err(MalformedPacket),
                        "{desc}; compression mode 0x{compression_mode:02x}; \
                         {len} of {headers_len} header bytes",
                    );
                }
            }
        }
    }

    /// zl-zipline#283: a compressed IPv4 header whose header length is
    /// shorter than an IPv4 header, or longer than the expanded packet, is
    /// refused (the checksum is computed over that length).
    #[test]
    fn test_expand_rejects_a_bad_ipv4_header_length() {
        // "UDP (NTP)", the first test case with a UDP payload.
        let (_, body) = TEST_CASES[3];
        let mut pkt = packet_of(body);
        let (metadata, pkt_body) = pkt.metadata_mut_and_body_mut();
        classifier::classify(metadata.five_tuple_mut(), pkt_body).unwrap();
        let ft = *pkt.metadata().five_tuple();
        let mode = CompressionMode::default();
        compress(mode, ft.l3_type, ft.l4_protocol, &mut pkt);
        let compressed = pkt.body().to_vec();

        for hl in [0u8, 4, 15] {
            // Keep only the compressed headers (IPv4 5 bytes, UDP 6), so the
            // expanded packet is 28 bytes, shorter than a 60-byte header.
            let mut cut = compressed[..11].to_vec();
            cut[0] = (hl << 4) | (cut[0] & 0x0f);
            let mut pkt = packet_of(&cut);
            assert_eq!(
                expand(mode, &ft, &mut pkt),
                Err(MalformedPacket),
                "header length {hl}"
            );
        }
    }

    /// Uncompressed packets, by description; the fast path's tests use
    /// them too.
    pub(crate) const TEST_CASES: &[(&str, &[u8])] = &[
        (
            "ICMP Echo (ping) request",
            &[
                0x45, 0x00, 0x00, 0x54, 0x46, 0xa2, 0x40, 0x00, 0x40, 0x01, 0x70, 0xb3, 0xc0, 0xa8,
                0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, 0x08, 0x00, 0x5d, 0x2e, 0xf6, 0xae, 0x00, 0x01,
                0x3c, 0xa0, 0xcc, 0x66, 0x00, 0x00, 0x00, 0x00, 0xda, 0x47, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            ],
        ),
        (
            "ICMPv6 Neighbor Soliciation",
            &[
                0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x0c, 0xbb, 0x7e, 0xa4, 0x55, 0xf1, 0x07, 0x9f, 0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xf1, 0x00, 0x01, 0x87, 0x00,
                0x1a, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0c, 0xbb, 0x7e, 0xa4, 0x55, 0xf1, 0x00, 0x01, 0x01, 0x01, 0xe4, 0x60, 0x17, 0xd8,
                0x9a, 0x4b,
            ],
        ),
        (
            "TCP mid-stream (TLS)",
            &[
                0x45, 0x00, 0x00, 0x4c, 0xc8, 0xa2, 0x40, 0x00, 0x2e, 0x06, 0xd7, 0x29, 0x17, 0x60,
                0x7c, 0x44, 0xc0, 0xa8, 0x58, 0x93, 0x01, 0xbb, 0xad, 0x18, 0xea, 0xfb, 0x7d, 0x53,
                0x23, 0xea, 0x6b, 0x90, 0x80, 0x18, 0x01, 0xf5, 0x5c, 0x7a, 0x00, 0x00, 0x01, 0x01,
                0x08, 0x0a, 0x49, 0xad, 0x26, 0x25, 0x74, 0xcf, 0x24, 0x4a, 0x17, 0x03, 0x03, 0x00,
                0x13, 0x3e, 0xf1, 0x3e, 0x45, 0xbc, 0x66, 0x69, 0xe7, 0xf1, 0x28, 0xb4, 0x60, 0x8a,
                0xaf, 0x1f, 0xef, 0x77, 0xe1, 0x56,
            ],
        ),
        (
            "UDP (NTP)",
            &[
                0x45, 0xb8, 0x00, 0x4c, 0x73, 0xb2, 0x40, 0x00, 0x35, 0x11, 0xe8, 0x2c, 0x47, 0xa2,
                0x88, 0x2c, 0xc0, 0xa8, 0x58, 0x93, 0x00, 0x7b, 0x00, 0x7b, 0x00, 0x38, 0x48, 0xcd,
                0x24, 0x03, 0x00, 0xe9, 0x00, 0x00, 0x02, 0xc1, 0x00, 0x00, 0x0c, 0xe8, 0xd0, 0x5a,
                0x90, 0x35, 0xed, 0x51, 0xb0, 0xa6, 0x40, 0x7f, 0x0b, 0xdf, 0x9d, 0x36, 0x66, 0xa5,
                0x07, 0x76, 0xe4, 0xb9, 0xed, 0x51, 0xb8, 0xac, 0x9f, 0x31, 0x21, 0x57, 0xed, 0x51,
                0xb8, 0xac, 0x9f, 0x3a, 0xb1, 0x67,
            ],
        ),
        (
            "TCPv6 mid-stream (SSH)",
            &[
                0x61, 0x06, 0x93, 0x47, 0x00, 0x54, 0x06, 0x40, 0xfd, 0x58, 0x97, 0x1a, 0xa5, 0xca,
                0x00, 0x00, 0xf6, 0x4d, 0x30, 0xff, 0xfe, 0x62, 0x06, 0x5e, 0xfd, 0x58, 0x97, 0x1a,
                0xa5, 0xca, 0x00, 0x00, 0xf6, 0x09, 0xbf, 0x26, 0x40, 0x3f, 0xa5, 0x6d, 0x00, 0x16,
                0x88, 0xf8, 0x9a, 0x8a, 0x13, 0x71, 0xa5, 0x52, 0x4d, 0x8b, 0x80, 0x18, 0x01, 0xf5,
                0xf8, 0x89, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x81, 0x81, 0x87, 0x22, 0xd4, 0xa6,
                0x96, 0xb2, 0xbf, 0x5a, 0x00, 0xd8, 0x79, 0xac, 0xdb, 0x79, 0xe8, 0xef, 0x8d, 0x6f,
                0x2c, 0x10, 0xe2, 0x9d, 0xa4, 0x4a, 0x55, 0x18, 0xc0, 0x59, 0x66, 0xfd, 0x0a, 0x49,
                0x02, 0xca, 0xce, 0x64, 0x26, 0x43, 0x74, 0x7a, 0x47, 0x76, 0xa2, 0x44, 0x0d, 0xf4,
                0x89, 0x78, 0xe1, 0x77, 0x75, 0xfa, 0x87, 0x27, 0x45, 0xe2, 0xcb, 0xbb,
            ],
        ),
        (
            "MDNSv6 query",
            &[
                0x60, 0x0f, 0x82, 0xc9, 0x00, 0x5d, 0x11, 0xff, 0xfd, 0x58, 0x97, 0x1a, 0xa5, 0xca,
                0x00, 0x00, 0xe6, 0x60, 0x17, 0xff, 0xfe, 0xd8, 0x9a, 0x4b, 0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x14, 0xe9,
                0x14, 0xe9, 0x00, 0x5d, 0xc0, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x04, 0x5f, 0x73, 0x6d, 0x62, 0x04, 0x5f, 0x74, 0x63, 0x70,
                0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x04, 0x5f, 0x69,
                0x70, 0x70, 0xc0, 0x11, 0x00, 0x0c, 0x00, 0x01, 0x05, 0x5f, 0x69, 0x70, 0x70, 0x73,
                0xc0, 0x11, 0x00, 0x0c, 0x00, 0x01, 0x08, 0x5f, 0x77, 0x65, 0x62, 0x64, 0x61, 0x76,
                0x73, 0xc0, 0x11, 0x00, 0x0c, 0x00, 0x01, 0x07, 0x5f, 0x77, 0x65, 0x62, 0x64, 0x61,
                0x76, 0xc0, 0x11, 0x00, 0x0c, 0x00, 0x01,
            ],
        ),
    ];
}
