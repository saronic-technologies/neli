use crate as neli;

use neli_proc_macros::neli_enum;

use crate::compatibility::{
    AF_NETLINK, AF_X25, AF_AX25, AF_ATMPVC, AF_PACKET, AF_ALG,
    NETLINK_ROUTE, NETLINK_UNUSED, NETLINK_USERSOCK, NETLINK_FIREWALL,
    NETLINK_SOCK_DIAG, NETLINK_NFLOG, NETLINK_XFRM, NETLINK_SELINUX,
    NETLINK_ISCSI, NETLINK_AUDIT, NETLINK_FIB_LOOKUP, NETLINK_CONNECTOR,
    NETLINK_NETFILTER, NETLINK_IP6_FW, NETLINK_DNRTMSG, NETLINK_KOBJECT_UEVENT,
    NETLINK_GENERIC, NETLINK_SCSITRANSPORT, NETLINK_ECRYPTFS, NETLINK_RDMA,
    NETLINK_CRYPTO,
};

/// General address families for sockets
#[neli_enum(serialized_type = "libc::c_int")]
pub enum AddrFamily {
    UnixOrLocal = libc::AF_UNIX,
    Inet = libc::AF_INET,
    Inet6 = libc::AF_INET6,
    Ipx = libc::AF_IPX,
    Netlink = AF_NETLINK,
    X25 = AF_X25,
    Ax25 = AF_AX25,
    Atmpvc = AF_ATMPVC,
    Appletalk = libc::AF_APPLETALK,
    Packet = AF_PACKET,
    Alg = AF_ALG,
}

/// Values for `nl_family` in `NlSocket`
#[neli_enum(serialized_type = "libc::c_int")]
pub enum NlFamily {
    Route = NETLINK_ROUTE,
    Unused = NETLINK_UNUSED,
    Usersock = NETLINK_USERSOCK,
    Firewall = NETLINK_FIREWALL,
    SockOrInetDiag = NETLINK_SOCK_DIAG,
    Nflog = NETLINK_NFLOG,
    Xfrm = NETLINK_XFRM,
    Selinux = NETLINK_SELINUX,
    Iscsi = NETLINK_ISCSI,
    Audit = NETLINK_AUDIT,
    FibLookup = NETLINK_FIB_LOOKUP,
    Connector = NETLINK_CONNECTOR,
    Netfilter = NETLINK_NETFILTER,
    Ip6Fw = NETLINK_IP6_FW,
    Dnrtmsg = NETLINK_DNRTMSG,
    KobjectUevent = NETLINK_KOBJECT_UEVENT,
    Generic = NETLINK_GENERIC,
    Scsitransport = NETLINK_SCSITRANSPORT,
    Ecryptfs = NETLINK_ECRYPTFS,
    Rdma = NETLINK_RDMA,
    Crypto = NETLINK_CRYPTO,
}
