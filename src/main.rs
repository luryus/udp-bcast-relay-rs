use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddrV4},
};

use anyhow::{anyhow, Context};
use clap::{arg, command, value_parser, Arg, ArgAction};
use libc::{CMSG_DATA, CMSG_FIRSTHDR};
use packet::{AsPacket, AsPacketMut, Builder};
use socket2::{Domain, MaybeUninitSlice, MsgHdrMut, Protocol, SockAddr, Socket, Type};
use socket_pktinfo::PktInfoUdpSocket;
use std::os::fd::AsRawFd;

struct BroadcastIf {
    dst_addr: Ipv4Addr,
    socket: Socket,
}

const TTL_ID_OFFSET: u16 = 64;

fn main() -> anyhow::Result<()> {
    let args = command!()
        .arg(Arg::new("id").value_parser(value_parser!(u16).range(1..99)))
        .arg(Arg::new("port").value_parser(value_parser!(u16).range(1..)))
        .arg(Arg::new("interface").action(ArgAction::Append))
        .get_matches();

    let id: u16 = *args.get_one("id").unwrap();
    let port: u16 = *args.get_one("port").unwrap();
    let bcast_interface_names: Vec<_> = args
        .get_many::<String>("interface")
        .unwrap()
        .map(|x| x.as_str())
        .collect();

    println!("{id}, {port}, {bcast_interface_names:?}");

    let sys_interfaces = netdev::interface::get_interfaces();
    let mut bcast_interfaces: Vec<BroadcastIf> = vec![];
    for int_name in bcast_interface_names {
        let Some(int) = sys_interfaces.iter().find(|i| i.name == int_name) else {
            return Err(anyhow!("Interface {int_name} not found"));
        };

        if !int.is_up() || int.is_loopback() {
            // Ignore
            continue;
        }

        let is_bcast_interface = int.is_broadcast();

        let addr = int
            .ipv4
            .first()
            .map(|a| {
                if is_bcast_interface {
                    a.broadcast()
                } else {
                    a.addr
                }
            })
            .context("No address found for interface {int_name}")?;

        let send_sock = Socket::new(Domain::IPV4, Type::RAW, None)?;
        send_sock.set_broadcast(true)?;
        send_sock.bind_device(Some(int.name.as_bytes()))?;
        send_sock.set_header_included(true)?;

        bcast_interfaces.push(BroadcastIf {
            dst_addr: addr,
            socket: send_sock,
        });
    }

    let rcv_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    unsafe { setsockopt(rcv_sock.as_raw_fd(), libc::IPPROTO_IP, libc::IP_RECVTTL, 1)? };
    unsafe { setsockopt(rcv_sock.as_raw_fd(), libc::IPPROTO_IP, libc::IP_PKTINFO, 1)? };
    let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port);
    rcv_sock.bind(&addr.into())?;

    let mut control_buf = vec![MaybeUninit::uninit(); 16 * 1024];
    let mut rcv_addr: SockAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
    let mut rcv_buf = vec![MaybeUninit::uninit(); 4096];

    loop {
        let mut rcv_buf_slices = [MaybeUninitSlice::new(&mut rcv_buf); 1];
        let mut header = MsgHdrMut::new()
            .with_control(&mut control_buf)
            .with_addr(&mut rcv_addr)
            .with_buffers(&mut rcv_buf_slices);
        let len = rcv_sock.recvmsg(&mut header, 0)?;
        if len == 0 {
            continue;
        }

        if header.control_len() == 0 {
            log::warn!("Control len zero in received packet");
            continue;
        }
        let controllen = header.control_len();

        let libc_hdr = libc::msghdr {
            msg_control: control_buf.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: controllen,
            msg_flags: 0,
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
        };

        let mut ttl: Option<u16> = None;
        let mut if_index: Option<u16> = None;

        let mut cmsg = unsafe { CMSG_FIRSTHDR(&libc_hdr) };
        while !cmsg.is_null() {
            if unsafe { (*cmsg).cmsg_type } == libc::IP_TTL {
                let ttl_ptr = unsafe { CMSG_DATA(cmsg) } as *const libc::c_int;
                ttl = unsafe { std::ptr::read_unaligned(ttl_ptr) }.try_into().ok();
            }

            if unsafe { (*cmsg).cmsg_type } == libc::IP_PKTINFO {
                let pi_ptr = unsafe { CMSG_DATA(cmsg) } as *const libc::in_pktinfo;
                let pi = unsafe { std::ptr::read_unaligned(pi_ptr) };
                if_index = pi.ipi_ifindex.try_into().ok();
            }

            cmsg = unsafe { libc::CMSG_NXTHDR(&libc_hdr, cmsg) };
        }

        let Some(ttl) = ttl else {
            log::warn!("TTL not found");
            continue;
        };
        let Some(if_index) = if_index else {
            log::warn!("Interface index not found");
            continue;
        };

        if ttl == TTL_ID_OFFSET + id {
            log::debug!("Got own pkg");
            continue;
        }

        log::debug!("Got remote pkg: TTL {ttl}, if {if_index}, from: {rcv_addr:?}");

        let rcv_addr = rcv_addr.as_socket_ipv4().context("rcv_addr not ipv4")?;

        let mut packet_buf = vec![0u8; 8192];

        for interface in &bcast_interfaces {
            packet_buf.fill(0);
            let mut udp_b =
                packet::ip::v4::Builder::with(packet::buffer::Slice::new(&mut packet_buf))?
                    .source(*rcv_addr.ip())?
                    .destination(interface.dst_addr)?
                    .id(0x1234)?
                    .ttl(ttl.clamp(0, u8::MAX.into()) as u8)?
                    .protocol(packet::ip::Protocol::Udp)?
                    .udp()?;

            let udp_payload = unsafe { slice_assume_init_ref(&rcv_buf[..len]) };
            let udp_packet = udp_b
                .source(rcv_addr.port())?
                .destination(port)?
                .payload(udp_payload)?
                .build()?;
            let a = SocketAddrV4::new(interface.dst_addr, port);
            interface.socket.send_to(udp_packet, &a.into())?;
        }
    }

    Ok(())
}

unsafe fn setsockopt<T>(
    socket: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    value: T,
) -> std::io::Result<()>
where
    T: Copy,
{
    let value = &value as *const T as *const libc::c_void;
    if libc::setsockopt(
        socket,
        level,
        name,
        value,
        std::mem::size_of::<T>() as libc::socklen_t,
    ) == 0
    {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Assuming all the elements are initialized, get a slice to them.
///
/// # Safety
///
/// It is up to the caller to guarantee that the `MaybeUninit<T>` elements
/// really are in an initialized state.
/// Calling this when the content is not yet fully initialized causes undefined behavior.
///
/// See [`assume_init_ref`] for more details and examples.
///
/// [`assume_init_ref`]: MaybeUninit::assume_init_ref
#[inline(always)]
pub const unsafe fn slice_assume_init_ref<T>(slice: &[MaybeUninit<T>]) -> &[T] {
    // SAFETY: casting `slice` to a `*const [T]` is safe since the caller guarantees that
    // `slice` is initialized, and `MaybeUninit` is guaranteed to have the same layout as `T`.
    // The pointer obtained is valid since it refers to memory owned by `slice` which is a
    // reference and thus guaranteed to be valid for reads.
    unsafe { &*(slice as *const [MaybeUninit<T>] as *const [T]) }
}
