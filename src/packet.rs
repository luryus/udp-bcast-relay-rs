use anyhow::bail;

pub struct Ipv4UdpPacket {
    buf: Vec<u8>,
    payload_len: u16
}

const UDP_PROTOCOL_NUMBER: u8 = 0x11;

const EMPTY_IPV4_HEADER: [u8; 20] = [
    0x45, 0x00, 0x00, 0x00,
    0x12, 0x34, 0x40, 0x00,
    0x00, UDP_PROTOCOL_NUMBER, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

const IPV4_LENGTH_OFFSET: usize = 2;
const IPV4_SRC_OFFSET: usize = 12;
const IPV4_DST_OFFSET: usize = 16;
const IPV4_TTL_OFFSET: usize = 8;
const IPV4_CHECKSUM_OFFSET: usize = 10;
const UDP_HEADER_OFFSET: usize = EMPTY_IPV4_HEADER.len();
const UDP_SRC_OFFSET: usize = UDP_HEADER_OFFSET;
const UDP_DST_OFFSET: usize = UDP_HEADER_OFFSET + 2;
const UDP_LENGTH_OFFSET: usize = UDP_HEADER_OFFSET + 4;
const UDP_CHECKSUM_OFFSET: usize = UDP_HEADER_OFFSET + 6;
const UDP_HEADER_LEN: usize = 8;

const TOTAL_HEADER_LEN: usize = UDP_HEADER_LEN + EMPTY_IPV4_HEADER.len();

impl Ipv4UdpPacket {
    fn total_len(&self) -> usize {
        TOTAL_HEADER_LEN + self.payload_len as usize
    }

    pub fn new(initial_capacity: u16) -> Self {
        let mut p = Self {
            buf: Vec::with_capacity(initial_capacity.into()),
            payload_len: 0,
        };
        p.buf.extend_from_slice(&EMPTY_IPV4_HEADER);
        p.buf.extend_from_slice(&[0u8; 8]);
        p
    }

    pub fn set_details(
        &mut self,
        src_ip: &[u8; 4],
        ttl: u8,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        if (u16::MAX as usize) < (TOTAL_HEADER_LEN + payload.len())
        {
            bail!("Payload too long");
        }

        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        let ip_len = EMPTY_IPV4_HEADER.len() as u16 + udp_len;

        self.buf[IPV4_SRC_OFFSET..IPV4_SRC_OFFSET+4].copy_from_slice(&src_ip[..]);
        self.buf[IPV4_LENGTH_OFFSET..IPV4_LENGTH_OFFSET+2].copy_from_slice(&ip_len.to_be_bytes());
        self.buf[IPV4_TTL_OFFSET] = ttl;

        self.buf[UDP_SRC_OFFSET..UDP_SRC_OFFSET+2].copy_from_slice(&src_port.to_be_bytes());
        self.buf[UDP_DST_OFFSET..UDP_DST_OFFSET+2].copy_from_slice(&dst_port.to_be_bytes());
        self.buf[UDP_LENGTH_OFFSET..UDP_LENGTH_OFFSET+2]
            .copy_from_slice(&((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes());

        self.buf.truncate(TOTAL_HEADER_LEN);
        self.buf.extend_from_slice(payload);
        self.payload_len = payload.len().try_into().unwrap();

        debug_assert_eq!(self.total_len(), self.buf.len());
        
        Ok(())
    }

    pub fn set_dst_ip(&mut self, dst_ip: &[u8; 4]) {
        self.buf[IPV4_DST_OFFSET..IPV4_DST_OFFSET+4].copy_from_slice(&dst_ip[..]);
    }


    pub fn update_checksums(&mut self) {
        self.buf[IPV4_CHECKSUM_OFFSET..IPV4_CHECKSUM_OFFSET + 2].fill(0);
        self.buf[UDP_CHECKSUM_OFFSET..UDP_CHECKSUM_OFFSET + 2].fill(0);

        let udp_len = self.payload_len + UDP_HEADER_LEN as u16;

        let udp_chksum = udp_checksum(
            udp_len,
            &self.buf[IPV4_SRC_OFFSET..IPV4_SRC_OFFSET + 8],
            &self.buf[UDP_HEADER_OFFSET..self.total_len()],
        );

        let ip_chksum = ipv4_checksum(&self.buf[0..EMPTY_IPV4_HEADER.len()]);

        self.buf[IPV4_CHECKSUM_OFFSET..IPV4_CHECKSUM_OFFSET + 2]
            .copy_from_slice(&ip_chksum.to_be_bytes());
        self.buf[UDP_CHECKSUM_OFFSET..UDP_CHECKSUM_OFFSET + 2]
            .copy_from_slice(&udp_chksum.to_be_bytes());
    }

    pub fn data(&self) -> &[u8] {
        &self.buf
    }
}

fn udp_checksum(udp_len: u16, ip_addrs: &[u8], udp_packet: &[u8]) -> u16 {
    let mut sum = 0x0011u16;
    sum = carrying_add(sum, udp_len);
    debug_assert_eq!(2 * 4, ip_addrs.len());

    let udp_packet_len = if udp_packet.len() % 2 == 1 {
        sum = carrying_add(sum, ((*udp_packet.last().unwrap()) as u16) << 8u16);
        udp_packet.len() - 1
    } else {
        udp_packet.len()
    };

    sum = ip_addrs.chunks_exact(2)
        .chain(udp_packet[0..udp_packet_len].chunks_exact(2))
        .map(|bs| (bs[0] as u16) << 8 | bs[1] as u16)
        .fold(sum, carrying_add);

    !sum
}

fn ipv4_checksum(ip_header: &[u8]) -> u16 {
    let sum = ip_header.chunks_exact(2)
        .map(|bs| (bs[0] as u16) << 8 | bs[1] as u16)
        .fold(0u16, carrying_add);
    
    !sum
}

#[inline]
fn carrying_add(a: u16, b: u16) -> u16 {
    let (res, carry) = a.overflowing_add(b);
    res + carry as u16
}

#[cfg(test)] 
mod test {
    use super::*;
    use etherparse::{Ipv4Slice, UdpSlice};

    #[test]
    fn test_packet() {
        let payload = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
        let mut p = Ipv4UdpPacket::new(128);
        p.set_details(&[127,0,0,1], 71, 11223, 33221, &payload).unwrap();
        p.set_dst_ip(&[192,168,0,255]);
        p.update_checksums();

        let d = p.data();   
        let ipv4 = Ipv4Slice::from_slice(d).unwrap();
        let udp = UdpSlice::from_slice(ipv4.payload().payload).unwrap();
        assert_eq!(udp.payload(), &payload);  
    }
}