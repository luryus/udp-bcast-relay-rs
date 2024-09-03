use std::{
    marker::PhantomData,
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddrV4},
};

use anyhow::{bail, Context};
use libc::{cmsghdr, in_pktinfo, CMSG_DATA, CMSG_FIRSTHDR, CMSG_NXTHDR};
use socket2::{MaybeUninitSlice, MsgHdrMut, SockAddr, Socket};

pub struct Cmsg<'a>(*mut cmsghdr, PhantomData<&'a Receiver<Received>>);
impl<'a> Cmsg<'a> {
    pub fn ttl(&self) -> Option<i32> {
        unsafe { self.get_if_type(libc::IP_TTL) }
    }

    pub fn pktinfo(&self) -> Option<in_pktinfo> {
        unsafe { self.get_if_type(libc::IP_PKTINFO) }
    }

    fn typ(&self) -> i32 {
        unsafe { *self.0 }.cmsg_type
    }

    unsafe fn get_if_type<T: Sized>(&self, typ: i32) -> Option<T> {
        (self.typ() == typ).then(|| self.get())
    }

    unsafe fn get<T: Sized>(&self) -> T {
        assert_eq!(size_of::<T>(), (*self.0).cmsg_len);

        let ptr = CMSG_DATA(self.0) as *const T;
        std::ptr::read_unaligned(ptr)
    }
}

pub trait ReceiverState {}
pub struct Empty;
pub struct Received;
impl ReceiverState for Empty {}
impl ReceiverState for Received {}
pub struct Receiver<S: ReceiverState> {
    socket: Socket,
    control_buf: Box<[MaybeUninit<u8>]>,
    rcv_buf: Box<[MaybeUninit<u8>]>,
    rcv_addr: SockAddr,
    control_len: usize,
    len: usize,
    state: PhantomData<S>,
}

impl Receiver<Empty> {
    fn with_socket(socket: Socket) -> Self {
        Self {
            socket,
            control_buf: vec![MaybeUninit::uninit(); 16 * 1024].into_boxed_slice(),
            rcv_buf: vec![MaybeUninit::uninit(); 4096].into_boxed_slice(),
            rcv_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into(),
            state: PhantomData,
            len: 0,
            control_len: 0,
        }
    }

    pub fn recvmsg(mut self) -> Result<Receiver<Received>, Box<(Receiver<Empty>, std::io::Error)>> {
        let mut rcv_buf_slices = [MaybeUninitSlice::new(&mut self.rcv_buf); 1];
        let mut header = MsgHdrMut::new()
            .with_control(&mut self.control_buf)
            .with_addr(&mut self.rcv_addr)
            .with_buffers(&mut rcv_buf_slices);
        let len = match self.socket.recvmsg(&mut header, 0) {
            Ok(l) => l,
            Err(e) => {
                self.rcv_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
                return Err(Box::new((self, e)));
            }
        };
        let control_len = header.control_len();

        Ok(Receiver {
            state: PhantomData,
            socket: self.socket,
            rcv_addr: self.rcv_addr,
            rcv_buf: self.rcv_buf,
            control_buf: self.control_buf,
            len,
            control_len,
        })
    }
}

impl Receiver<Received> {
    pub fn reset(self) -> Receiver<Empty> {
        Receiver {
            state: PhantomData,
            socket: self.socket,
            rcv_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into(),
            rcv_buf: self.rcv_buf,
            control_buf: self.control_buf,
            len: 0,
            control_len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn control_len(&self) -> usize {
        self.control_len
    }
    pub fn rcv_addr(&self) -> &SockAddr {
        &self.rcv_addr
    }
    pub fn payload(&self) -> &[u8] {
        unsafe { slice_assume_init_ref(&self.rcv_buf[..self.len]) }
    }

    pub fn ttl_and_if_index(&self) -> anyhow::Result<(u8, u32)> {
        let mut ttl = None;
        let mut if_index = None;

        for cmsg in self.cmsgs() {
            if let Some(t) = cmsg.ttl() {
                ttl = Some(t);
            } else if let Some(pi) = cmsg.pktinfo() {
                if_index = Some(pi.ipi_ifindex)
            }

            if let Some((ttl, if_index)) = ttl.zip(if_index) {
                return Ok((
                    ttl.try_into().context("TTL out of range")?,
                    if_index.try_into().context("if_index out of range")?,
                ));
            }
        }

        if ttl.is_none() {
            bail!("ttl cmsg not received");
        }
        bail!("pktinfo cmsg not received");
    }

    fn control(&self) -> &[u8] {
        // SAFETY: Receiver<Received> can only be constructed via a valid
        // call to recvmsg, which leaves the control_buf and control_len properly
        // initialized.
        unsafe { slice_assume_init_ref(&self.control_buf[..self.control_len]) }
    }

    fn cmsgs(&self) -> impl Iterator<Item = Cmsg> {
        // Make a new instance of a msg header, we need this for the CMSG_ things
        let libc_hdr = libc::msghdr {
            msg_control: self.control().as_ptr() as *mut libc::c_void,
            msg_controllen: self.control().len(),
            msg_flags: 0,
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
        };

        let mut current: *mut libc::cmsghdr = std::ptr::null_mut();
        std::iter::from_fn(move || {
            // SAFETY: the header is known to be valid msghdr, so it should be totally
            // safe to call the CMSG macros
            if current.is_null() {
                // First
                current = unsafe { CMSG_FIRSTHDR(&libc_hdr) };
            } else {
                // Subsequent
                current = unsafe { CMSG_NXTHDR(&libc_hdr, current) };
            }

            match current.is_null() {
                false => Some(Cmsg(current, PhantomData)),
                true => None,
            }
        })
    }
}

impl From<Socket> for Receiver<Empty> {
    fn from(value: Socket) -> Self {
        Self::with_socket(value)
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
const unsafe fn slice_assume_init_ref<T>(slice: &[MaybeUninit<T>]) -> &[T] {
    // SAFETY: casting `slice` to a `*const [T]` is safe since the caller guarantees that
    // `slice` is initialized, and `MaybeUninit` is guaranteed to have the same layout as `T`.
    // The pointer obtained is valid since it refers to memory owned by `slice` which is a
    // reference and thus guaranteed to be valid for reads.
    unsafe { &*(slice as *const [MaybeUninit<T>] as *const [T]) }
}
