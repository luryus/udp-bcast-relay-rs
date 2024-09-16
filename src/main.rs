use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{anyhow, bail, Context};
use clap::{command, value_parser, Arg, ArgAction};
use netdev::Interface;
use packet::Ipv4UdpPacket;
use socket2::{Domain, Protocol, Socket, Type};
use std::os::fd::AsRawFd;
use stderrlog::LogLevelNum;

use receiver::*;

struct BroadcastIf {
    dst_addr: Ipv4Addr,
    index: u32,
    socket: Socket,
}

mod packet;
mod receiver;

const TTL_ID_OFFSET: u8 = 64;

fn main() -> anyhow::Result<()> {
    let args = command!()
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Print more logs"),
        )
        .arg(
            Arg::new("id")
                .required(true)
                .help("System-unique ID for this instance")
                .value_parser(value_parser!(u8).range(1..99)),
        )
        .arg(
            Arg::new("port")
                .required(true)
                .help("UDP port number to relay broadcasts for")
                .value_parser(value_parser!(u16).range(1..)),
        )
        .arg(
            Arg::new("interface")
                .required(true)
                .help("Interface names to relay broadcasts between")
                .action(ArgAction::Append),
        )
        .get_matches();

    stderrlog::new()
        .module(module_path!())
        .verbosity(if args.get_flag("verbose") {
            LogLevelNum::Debug
        } else {
            LogLevelNum::Info
        })
        .init()
        .unwrap();

    let id: u8 = *args.get_one("id").unwrap();
    let port: u16 = *args.get_one("port").unwrap();
    let bcast_interface_names: Vec<_> = args
        .get_many::<String>("interface")
        .unwrap()
        .map(|x| x.as_str())
        .collect();

    let sys_interfaces = netdev::interface::get_interfaces();
    let mut bcast_interfaces: Vec<BroadcastIf> = vec![];
    for if_name in bcast_interface_names {
        let bcast_if = setup_interface_listen(if_name, &sys_interfaces)
            .with_context(|| format!("Setting up interface {if_name} failed"))?;
        bcast_interfaces.push(bcast_if);
    }

    let rcv_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("rcv_sock Socket::new")?;
    unsafe { setsockopt(rcv_sock.as_raw_fd(), libc::IPPROTO_IP, libc::IP_RECVTTL, 1) }
        .context("setsockopt IP_RECVTTL")?;
    unsafe { setsockopt(rcv_sock.as_raw_fd(), libc::IPPROTO_IP, libc::IP_PKTINFO, 1) }
        .context("setsockopt IP_PKTINFO")?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    rcv_sock.bind(&addr.into()).context("rcv_sock bind")?;

    let mut packet = Ipv4UdpPacket::new(8192);
    let mut receiver: Receiver<Empty> = rcv_sock.into();

    let mut errors = 0;

    loop {
        let received = match receiver.recvmsg() {
            Ok(r) => r,
            Err(b) => {
                log::warn!("Error on receive: {}", b.1);
                errors += 1;
                if errors >= 5 {
                    return Err(b.1).context("Too many errors");
                }
                receiver = b.0;
                continue;
            }
        };

        let handle_res = handle_received(&received, id, port, &bcast_interfaces, &mut packet);
        match handle_res {
            Ok(()) => {
                errors = 0;
            }
            Err(e) => {
                log::warn!("Error while handling packet: {e}");
                errors += 1;
                if errors >= 5 {
                    return Err(e).context("Too many errors");
                }
            }
        }

        receiver = received.reset();
    }
}

fn handle_received(
    r: &Receiver<Received>,
    id: u8,
    port: u16,
    broadcast_ifs: &[BroadcastIf],
    packet: &mut Ipv4UdpPacket,
) -> anyhow::Result<()> {
    if r.len() == 0 {
        return Ok(());
    }

    if r.control_len() == 0 {
        bail!("Control length was zero");
    }

    let (ttl, if_index) = r.ttl_and_if_index()?;

    if ttl == TTL_ID_OFFSET + id {
        log::debug!("Got own pkg");
        return Ok(());
    }

    let rcv_addr = r.rcv_addr().as_socket_ipv4().context("rcv_addr not ipv4")?;
    log::debug!("Got remote pkg: TTL {ttl}, if {if_index}, from: {rcv_addr:?}");

    packet.set_details(
        &rcv_addr.ip().octets(),
        TTL_ID_OFFSET + id,
        rcv_addr.port(),
        port,
        r.payload(),
    )?;

    for interface in broadcast_ifs {
        if interface.index == if_index {
            continue;
        }

        packet.set_dst_ip(&interface.dst_addr.octets());

        packet.update_checksums();
        let a = SocketAddrV4::new(interface.dst_addr, port);
        interface.socket.send_to(packet.data(), &a.into())?;
        log::debug!("Sent packet to {a}");
    }

    Ok(())
}

fn setup_interface_listen(
    if_name: &str,
    sys_interfaces: &[Interface],
) -> anyhow::Result<BroadcastIf> {
    let int = sys_interfaces
        .iter()
        .find(|i| i.name == if_name)
        .context("Interface not found")?;

    if !int.is_up() || int.is_loopback() {
        // Ignore
        return Err(anyhow!("Interface is not up or is loopback"));
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
        .context("No address found for interface")?;

    let send_sock = Socket::new(
        libc::AF_INET.into(),
        Type::RAW,
        Some(libc::IPPROTO_RAW.into()),
    )
    .context("Socket::new")?;

    send_sock
        .set_header_included(true)
        .context("set_header_included")?;
    send_sock.set_broadcast(true).context("set_broadcast")?;
    send_sock
        .bind_device(Some(int.name.as_bytes()))
        .context("bind_device")?;

    log::debug!("Listening on interface {}", if_name);

    Ok(BroadcastIf {
        dst_addr: addr,
        socket: send_sock,
        index: int.index,
    })
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
