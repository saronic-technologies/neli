//! OSX compatibility layer for Linux netlink constants and structures.
//!
//! This module provides definitions for netlink-related constants, structures,
//! and enums that are typically available on Linux but may not be present on OSX.
//! It enables cross-platform compatibility for netlink socket programming.

use libc::{c_ushort, c_int, c_uint, c_uchar};

/// Netlink socket address structure.
/// 
/// This structure represents a netlink socket address, similar to sockaddr_in
/// for internet sockets.
#[allow(non_camel_case_types)]
pub struct sockaddr_nl {
    /// Address family (should be AF_NETLINK)
    pub nl_family: u16,
    /// Padding for alignment
    nl_pad: c_ushort,
    /// Process ID or port ID
    pub nl_pid: u32,
    /// Multicast group mask
    pub nl_groups: u32,
}

/// Process connector multicast operations.
/// 
/// These values are used to control process event multicast subscriptions.
#[allow(non_camel_case_types)]
pub enum proc_cn_mcast_op {
    /// Start listening to process events
    PROC_CN_MCAST_LISTEN = 1,
    /// Stop listening to process events  
    PROC_CN_MCAST_IGNORE = 2,
}

/// Process connector event types.
/// 
/// These flags specify which process events should be monitored.
#[allow(non_camel_case_types)]
pub enum proc_cn_event {
    /// No event
    PROC_EVENT_NONE = 0x00000000,
    /// Process fork event
    PROC_EVENT_FORK = 0x00000001,
    /// Process exec event
    PROC_EVENT_EXEC = 0x00000002,
    /// User ID change event
    PROC_EVENT_UID = 0x00000004,
    /// Group ID change event
    PROC_EVENT_GID = 0x00000040,
    /// Session ID change event
    PROC_EVENT_SID = 0x00000080,
    /// Ptrace event
    PROC_EVENT_PTRACE = 0x00000100,
    /// Command name change event
    PROC_EVENT_COMM = 0x00000200,
    /// Non-zero exit event
    PROC_EVENT_NONZERO_EXIT = 0x20000000,
    /// Core dump event
    PROC_EVENT_COREDUMP = 0x40000000,
    /// Process exit event
    PROC_EVENT_EXIT = 0x80000000,
}

/// Process connector index
pub const CN_IDX_PROC: c_uint = 0x1;
/// Process connector value
pub const CN_VAL_PROC: c_uint = 0x1;
/// CIFS connector index
pub const CN_IDX_CIFS: c_uint = 0x2;
/// CIFS connector value
pub const CN_VAL_CIFS: c_uint = 0x1;
/// W1 connector index
pub const CN_W1_IDX: c_uint = 0x3;
/// W1 connector value
pub const CN_W1_VAL: c_uint = 0x1;
/// V86D connector index
pub const CN_IDX_V86D: c_uint = 0x4;
/// V86D UVESAFB connector value
pub const CN_VAL_V86D_UVESAFB: c_uint = 0x1;
/// Block device connector index
pub const CN_IDX_BB: c_uint = 0x5;
/// DST connector index
pub const CN_DST_IDX: c_uint = 0x6;
/// DST connector value
pub const CN_DST_VAL: c_uint = 0x1;
/// Device mapper connector index
pub const CN_IDX_DM: c_uint = 0x7;
/// Device mapper userspace log connector value
pub const CN_VAL_DM_USERSPACE_LOG: c_uint = 0x1;
/// DRBD connector index
pub const CN_IDX_DRBD: c_uint = 0x8;
/// DRBD connector value
pub const CN_VAL_DRBD: c_uint = 0x1;
/// KVP connector index
pub const CN_KVP_IDX: c_uint = 0x9;
/// KVP connector value
pub const CN_KVP_VAL: c_uint = 0x1;
/// VSS connector index
pub const CN_VSS_IDX: c_uint = 0xA;
/// VSS connector value
pub const CN_VSS_VAL: c_uint = 0x1;

/// Netfilter netlink group: none
pub const NFNLGRP_NONE: c_int = 0;
/// Netfilter netlink group: new connection tracking entries
pub const NFNLGRP_CONNTRACK_NEW: c_int = 1;
/// Netfilter netlink group: connection tracking updates
pub const NFNLGRP_CONNTRACK_UPDATE: c_int = 2;
/// Netfilter netlink group: connection tracking entry destruction
pub const NFNLGRP_CONNTRACK_DESTROY: c_int = 3;
/// Netfilter netlink group: new connection tracking expectations
pub const NFNLGRP_CONNTRACK_EXP_NEW: c_int = 4;
/// Netfilter netlink group: connection tracking expectation updates
pub const NFNLGRP_CONNTRACK_EXP_UPDATE: c_int = 5;
/// Netfilter netlink group: connection tracking expectation destruction
pub const NFNLGRP_CONNTRACK_EXP_DESTROY: c_int = 6;
/// Netfilter netlink group: nftables events
pub const NFNLGRP_NFTABLES: c_int = 7;
/// Netfilter netlink group: accounting quota events
pub const NFNLGRP_ACCT_QUOTA: c_int = 8;
/// Netfilter netlink group: packet tracing events
pub const NFNLGRP_NFTRACE: c_int = 9;

/// Netfilter netlink protocol version 0
pub const NFNETLINK_V0: c_int = 0;

/// Netfilter netlink subsystem: none
pub const NFNL_SUBSYS_NONE: c_int = 0;
/// Netfilter netlink subsystem: connection tracking
pub const NFNL_SUBSYS_CTNETLINK: c_int = 1;
/// Netfilter netlink subsystem: connection tracking expectations
pub const NFNL_SUBSYS_CTNETLINK_EXP: c_int = 2;
/// Netfilter netlink subsystem: packet queue
pub const NFNL_SUBSYS_QUEUE: c_int = 3;
/// Netfilter netlink subsystem: userspace logging
pub const NFNL_SUBSYS_ULOG: c_int = 4;
/// Netfilter netlink subsystem: OS fingerprinting
pub const NFNL_SUBSYS_OSF: c_int = 5;
/// Netfilter netlink subsystem: IP sets
pub const NFNL_SUBSYS_IPSET: c_int = 6;
/// Netfilter netlink subsystem: accounting
pub const NFNL_SUBSYS_ACCT: c_int = 7;
/// Netfilter netlink subsystem: connection tracking timeout
pub const NFNL_SUBSYS_CTNETLINK_TIMEOUT: c_int = 8;
/// Netfilter netlink subsystem: connection tracking helper
pub const NFNL_SUBSYS_CTHELPER: c_int = 9;
/// Netfilter netlink subsystem: nftables
pub const NFNL_SUBSYS_NFTABLES: c_int = 10;
/// Netfilter netlink subsystem: nftables compatibility
pub const NFNL_SUBSYS_NFT_COMPAT: c_int = 11;
/// Netfilter netlink subsystem: hooks
pub const NFNL_SUBSYS_HOOK: c_int = 12;
/// Netfilter netlink subsystem count
pub const NFNL_SUBSYS_COUNT: c_int = 13;

/// Netfilter netlink message: batch begin
pub const NFNL_MSG_BATCH_BEGIN: c_int = NLMSG_MIN_TYPE;
/// Netfilter netlink message: batch end
pub const NFNL_MSG_BATCH_END: c_int = NLMSG_MIN_TYPE + 1;

/// Netfilter netlink batch: unspecified
pub const NFNL_BATCH_UNSPEC: c_int = 0;
/// Netfilter netlink batch: generation ID
pub const NFNL_BATCH_GENID: c_int = 1;

/// Netfilter userspace log message: packet
pub const NFULNL_MSG_PACKET: c_int = 0;
/// Netfilter userspace log message: configuration
pub const NFULNL_MSG_CONFIG: c_int = 1;

/// Netfilter userspace log VLAN attribute: unspecified
pub const NFULA_VLAN_UNSPEC: c_int = 0;
/// Netfilter userspace log VLAN attribute: protocol
pub const NFULA_VLAN_PROTO: c_int = 1;
/// Netfilter userspace log VLAN attribute: TCI
pub const NFULA_VLAN_TCI: c_int = 2;

/// Netfilter userspace log attribute: unspecified
pub const NFULA_UNSPEC: c_int = 0;
/// Netfilter userspace log attribute: packet header
pub const NFULA_PACKET_HDR: c_int = 1;
/// Netfilter userspace log attribute: mark
pub const NFULA_MARK: c_int = 2;
/// Netfilter userspace log attribute: timestamp
pub const NFULA_TIMESTAMP: c_int = 3;
/// Netfilter userspace log attribute: input device index
pub const NFULA_IFINDEX_INDEV: c_int = 4;
/// Netfilter userspace log attribute: output device index
pub const NFULA_IFINDEX_OUTDEV: c_int = 5;
/// Netfilter userspace log attribute: physical input device index
pub const NFULA_IFINDEX_PHYSINDEV: c_int = 6;
/// Netfilter userspace log attribute: physical output device index
pub const NFULA_IFINDEX_PHYSOUTDEV: c_int = 7;
/// Netfilter userspace log attribute: hardware address
pub const NFULA_HWADDR: c_int = 8;
/// Netfilter userspace log attribute: payload
pub const NFULA_PAYLOAD: c_int = 9;
/// Netfilter userspace log attribute: prefix
pub const NFULA_PREFIX: c_int = 10;
/// Netfilter userspace log attribute: user ID
pub const NFULA_UID: c_int = 11;
/// Netfilter userspace log attribute: sequence number
pub const NFULA_SEQ: c_int = 12;
/// Netfilter userspace log attribute: global sequence number
pub const NFULA_SEQ_GLOBAL: c_int = 13;
/// Netfilter userspace log attribute: group ID
pub const NFULA_GID: c_int = 14;
/// Netfilter userspace log attribute: hardware type
pub const NFULA_HWTYPE: c_int = 15;
/// Netfilter userspace log attribute: hardware header
pub const NFULA_HWHEADER: c_int = 16;
/// Netfilter userspace log attribute: hardware length
pub const NFULA_HWLEN: c_int = 17;
/// Netfilter userspace log attribute: connection tracking info
pub const NFULA_CT: c_int = 18;
/// Netfilter userspace log attribute: connection tracking additional info
pub const NFULA_CT_INFO: c_int = 19;
/// Netfilter userspace log attribute: VLAN info
pub const NFULA_VLAN: c_int = 20;
/// Netfilter userspace log attribute: layer 2 header
pub const NFULA_L2HDR: c_int = 21;

/// Netfilter userspace log config command: none
pub const NFULNL_CFG_CMD_NONE: c_int = 0;
/// Netfilter userspace log config command: bind
pub const NFULNL_CFG_CMD_BIND: c_int = 1;
/// Netfilter userspace log config command: unbind
pub const NFULNL_CFG_CMD_UNBIND: c_int = 2;
/// Netfilter userspace log config command: protocol family bind
pub const NFULNL_CFG_CMD_PF_BIND: c_int = 3;
/// Netfilter userspace log config command: protocol family unbind
pub const NFULNL_CFG_CMD_PF_UNBIND: c_int = 4;

/// Netfilter userspace log config attribute: unspecified
pub const NFULA_CFG_UNSPEC: c_int = 0;
/// Netfilter userspace log config attribute: command
pub const NFULA_CFG_CMD: c_int = 1;
/// Netfilter userspace log config attribute: mode
pub const NFULA_CFG_MODE: c_int = 2;
/// Netfilter userspace log config attribute: netlink buffer size
pub const NFULA_CFG_NLBUFSIZ: c_int = 3;
/// Netfilter userspace log config attribute: timeout
pub const NFULA_CFG_TIMEOUT: c_int = 4;
/// Netfilter userspace log config attribute: queue threshold
pub const NFULA_CFG_QTHRESH: c_int = 5;
/// Netfilter userspace log config attribute: flags
pub const NFULA_CFG_FLAGS: c_int = 6;

/// Netfilter userspace log copy mode: none
pub const NFULNL_COPY_NONE: c_int = 0x00;
/// Netfilter userspace log copy mode: metadata only
pub const NFULNL_COPY_META: c_int = 0x01;
/// Netfilter userspace log copy mode: packet data
pub const NFULNL_COPY_PACKET: c_int = 0x02;

/// Netfilter userspace log config flag: sequence numbers
pub const NFULNL_CFG_F_SEQ: c_int = 0x0001;
/// Netfilter userspace log config flag: global sequence numbers
pub const NFULNL_CFG_F_SEQ_GLOBAL: c_int = 0x0002;
/// Netfilter userspace log config flag: connection tracking
pub const NFULNL_CFG_F_CONNTRACK: c_int = 0x0004;

pub const MSG_OOB: c_int = 1;
pub const MSG_PEEK: c_int = 2;
pub const MSG_DONTROUTE: c_int = 4;
pub const MSG_CTRUNC: c_int = 8;
pub const MSG_TRUNC: c_int = 0x20;
pub const MSG_DONTWAIT: c_int = 0x40;
pub const MSG_EOR: c_int = 0x80;
pub const MSG_WAITALL: c_int = 0x100;
pub const MSG_FIN: c_int = 0x200;
pub const MSG_SYN: c_int = 0x400;
pub const MSG_CONFIRM: c_int = 0x800;
pub const MSG_RST: c_int = 0x1000;
pub const MSG_ERRQUEUE: c_int = 0x2000;
pub const MSG_NOSIGNAL: c_int = 0x4000;
pub const MSG_MORE: c_int = 0x8000;
pub const MSG_WAITFORONE: c_int = 0x10000;
pub const MSG_FASTOPEN: c_int = 0x20000000;
pub const MSG_CMSG_CLOEXEC: c_int = 0x40000000;

pub const NLMSG_NOOP: c_int = 0x1;
pub const NLMSG_ERROR: c_int = 0x2;
pub const NLMSG_DONE: c_int = 0x3;
pub const NLMSG_OVERRUN: c_int = 0x4;
pub const NLMSG_MIN_TYPE: c_int = 0x10;

pub const GENL_NAMSIZ: c_int = 16;

pub const GENL_MIN_ID: c_int = NLMSG_MIN_TYPE;
pub const GENL_MAX_ID: c_int = 1023;

pub const GENL_ADMIN_PERM: c_int = 0x01;
pub const GENL_CMD_CAP_DO: c_int = 0x02;
pub const GENL_CMD_CAP_DUMP: c_int = 0x04;
pub const GENL_CMD_CAP_HASPOL: c_int = 0x08;

pub const GENL_ID_CTRL: c_int = NLMSG_MIN_TYPE;

pub const CTRL_CMD_UNSPEC: c_int = 0;
pub const CTRL_CMD_NEWFAMILY: c_int = 1;
pub const CTRL_CMD_DELFAMILY: c_int = 2;
pub const CTRL_CMD_GETFAMILY: c_int = 3;
pub const CTRL_CMD_NEWOPS: c_int = 4;
pub const CTRL_CMD_DELOPS: c_int = 5;
pub const CTRL_CMD_GETOPS: c_int = 6;
pub const CTRL_CMD_NEWMCAST_GRP: c_int = 7;
pub const CTRL_CMD_DELMCAST_GRP: c_int = 8;
pub const CTRL_CMD_GETMCAST_GRP: c_int = 9;

pub const CTRL_ATTR_UNSPEC: c_int = 0;
pub const CTRL_ATTR_FAMILY_ID: c_int = 1;
pub const CTRL_ATTR_FAMILY_NAME: c_int = 2;
pub const CTRL_ATTR_VERSION: c_int = 3;
pub const CTRL_ATTR_HDRSIZE: c_int = 4;
pub const CTRL_ATTR_MAXATTR: c_int = 5;
pub const CTRL_ATTR_OPS: c_int = 6;
pub const CTRL_ATTR_MCAST_GROUPS: c_int = 7;

pub const CTRL_ATTR_OP_UNSPEC: c_int = 0;
pub const CTRL_ATTR_OP_ID: c_int = 1;
pub const CTRL_ATTR_OP_FLAGS: c_int = 2;

pub const CTRL_ATTR_MCAST_GRP_UNSPEC: c_int = 0;
pub const CTRL_ATTR_MCAST_GRP_NAME: c_int = 1;
pub const CTRL_ATTR_MCAST_GRP_ID: c_int = 2;

pub const NLA_ALIGNTO: c_int = 4;

pub const NETLINK_ROUTE: c_int = 0;
pub const NETLINK_UNUSED: c_int = 1;
pub const NETLINK_USERSOCK: c_int = 2;
pub const NETLINK_FIREWALL: c_int = 3;
pub const NETLINK_SOCK_DIAG: c_int = 4;
pub const NETLINK_NFLOG: c_int = 5;
pub const NETLINK_XFRM: c_int = 6;
pub const NETLINK_SELINUX: c_int = 7;
pub const NETLINK_ISCSI: c_int = 8;
pub const NETLINK_AUDIT: c_int = 9;
pub const NETLINK_FIB_LOOKUP: c_int = 10;
pub const NETLINK_CONNECTOR: c_int = 11;
pub const NETLINK_NETFILTER: c_int = 12;
pub const NETLINK_IP6_FW: c_int = 13;
pub const NETLINK_DNRTMSG: c_int = 14;
pub const NETLINK_KOBJECT_UEVENT: c_int = 15;
pub const NETLINK_GENERIC: c_int = 16;
pub const NETLINK_SCSITRANSPORT: c_int = 18;
pub const NETLINK_ECRYPTFS: c_int = 19;
pub const NETLINK_RDMA: c_int = 20;
pub const NETLINK_CRYPTO: c_int = 21;
pub const NETLINK_INET_DIAG: c_int = NETLINK_SOCK_DIAG;

pub const NLM_F_REQUEST: c_int = 1;
pub const NLM_F_MULTI: c_int = 2;
pub const NLM_F_ACK: c_int = 4;
pub const NLM_F_ECHO: c_int = 8;
pub const NLM_F_DUMP_INTR: c_int = 16;
pub const NLM_F_DUMP_FILTERED: c_int = 32;

pub const NLM_F_ROOT: c_int = 0x100;
pub const NLM_F_MATCH: c_int = 0x200;
pub const NLM_F_ATOMIC: c_int = 0x400;
pub const NLM_F_DUMP: c_int = NLM_F_ROOT | NLM_F_MATCH;

pub const NLM_F_REPLACE: c_int = 0x100;
pub const NLM_F_EXCL: c_int = 0x200;
pub const NLM_F_CREATE: c_int = 0x400;
pub const NLM_F_APPEND: c_int = 0x800;

pub const NLM_F_NONREC: c_int = 0x100;
pub const NLM_F_BULK: c_int = 0x200;

pub const NLM_F_CAPPED: c_int = 0x100;
pub const NLM_F_ACK_TLVS: c_int = 0x200;

pub const NLA_F_NESTED: c_int = 1 << 15;
pub const NLA_F_NET_BYTEORDER: c_int = 1 << 14;
pub const NLA_TYPE_MASK: c_int = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

pub const SOCK_CLOEXEC: c_int = libc::O_CLOEXEC;

pub const NETLINK_ADD_MEMBERSHIP: c_int = 1;
pub const NETLINK_DROP_MEMBERSHIP: c_int = 2;
pub const NETLINK_PKTINFO: c_int = 3;
pub const NETLINK_BROADCAST_ERROR: c_int = 4;
pub const NETLINK_NO_ENOBUFS: c_int = 5;
pub const NETLINK_RX_RING: c_int = 6;
pub const NETLINK_TX_RING: c_int = 7;
pub const NETLINK_LISTEN_ALL_NSID: c_int = 8;
pub const NETLINK_LIST_MEMBERSHIPS: c_int = 9;
pub const NETLINK_CAP_ACK: c_int = 10;
pub const NETLINK_EXT_ACK: c_int = 11;
pub const NETLINK_GET_STRICT_CHK: c_int = 12;

pub const NUD_NONE: u16 = 0x00;
pub const NUD_INCOMPLETE: u16 = 0x01;
pub const NUD_REACHABLE: u16 = 0x02;
pub const NUD_STALE: u16 = 0x04;
pub const NUD_DELAY: u16 = 0x08;
pub const NUD_PROBE: u16 = 0x10;
pub const NUD_FAILED: u16 = 0x20;
pub const NUD_NOARP: u16 = 0x40;
pub const NUD_PERMANENT: u16 = 0x80;

pub const NTF_USE: u8 = 0x01;
pub const NTF_SELF: u8 = 0x02;
pub const NTF_MASTER: u8 = 0x04;
pub const NTF_PROXY: u8 = 0x08;
pub const NTF_ROUTER: u8 = 0x80;

pub const IFA_UNSPEC: c_ushort = 0;
pub const IFA_ADDRESS: c_ushort = 1;
pub const IFA_LOCAL: c_ushort = 2;
pub const IFA_LABEL: c_ushort = 3;
pub const IFA_BROADCAST: c_ushort = 4;
pub const IFA_ANYCAST: c_ushort = 5;
pub const IFA_CACHEINFO: c_ushort = 6;
pub const IFA_MULTICAST: c_ushort = 7;
pub const IFA_FLAGS: c_ushort = 8;

pub const IFA_F_SECONDARY: u32 = 0x01;
pub const IFA_F_TEMPORARY: u32 = 0x01;
pub const IFA_F_NODAD: u32 = 0x02;
pub const IFA_F_OPTIMISTIC: u32 = 0x04;
pub const IFA_F_DADFAILED: u32 = 0x08;
pub const IFA_F_HOMEADDRESS: u32 = 0x10;
pub const IFA_F_DEPRECATED: u32 = 0x20;
pub const IFA_F_TENTATIVE: u32 = 0x40;
pub const IFA_F_PERMANENT: u32 = 0x80;
pub const IFA_F_MANAGETEMPADDR: u32 = 0x100;
pub const IFA_F_NOPREFIXROUTE: u32 = 0x200;
pub const IFA_F_MCAUTOJOIN: u32 = 0x400;
pub const IFA_F_STABLE_PRIVACY: u32 = 0x800;

pub const IFF_LOWER_UP: c_int = 0x10000;
pub const IFF_DORMANT: c_int = 0x20000;
pub const IFF_ECHO: c_int = 0x40000;

pub const IFF_MASTER: c_int = 0x400;
pub const IFF_SLAVE: c_int = 0x800;
pub const IFF_PORTSEL: c_int = 0x2000;
pub const IFF_AUTOMEDIA: c_int = 0x4000;
pub const IFF_DYNAMIC: c_int = 0x8000;

pub const ARPHRD_NETROM: u16 = 0;
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_EETHER: u16 = 2;
pub const ARPHRD_AX25: u16 = 3;
pub const ARPHRD_PRONET: u16 = 4;
pub const ARPHRD_CHAOS: u16 = 5;
pub const ARPHRD_IEEE802: u16 = 6;
pub const ARPHRD_ARCNET: u16 = 7;
pub const ARPHRD_APPLETLK: u16 = 8;
pub const ARPHRD_DLCI: u16 = 15;
pub const ARPHRD_ATM: u16 = 19;
pub const ARPHRD_METRICOM: u16 = 23;
pub const ARPHRD_IEEE1394: u16 = 24;
pub const ARPHRD_EUI64: u16 = 27;
pub const ARPHRD_INFINIBAND: u16 = 32;

pub const ARPHRD_SLIP: u16 = 256;
pub const ARPHRD_CSLIP: u16 = 257;
pub const ARPHRD_SLIP6: u16 = 258;
pub const ARPHRD_CSLIP6: u16 = 259;
pub const ARPHRD_RSRVD: u16 = 260;
pub const ARPHRD_ADAPT: u16 = 264;
pub const ARPHRD_ROSE: u16 = 270;
pub const ARPHRD_X25: u16 = 271;
pub const ARPHRD_HWX25: u16 = 272;
pub const ARPHRD_CAN: u16 = 280;
pub const ARPHRD_PPP: u16 = 512;
pub const ARPHRD_CISCO: u16 = 513;
pub const ARPHRD_HDLC: u16 = ARPHRD_CISCO;
pub const ARPHRD_LAPB: u16 = 516;
pub const ARPHRD_DDCMP: u16 = 517;
pub const ARPHRD_RAWHDLC: u16 = 518;

pub const ARPHRD_TUNNEL: u16 = 768;
pub const ARPHRD_TUNNEL6: u16 = 769;
pub const ARPHRD_FRAD: u16 = 770;
pub const ARPHRD_SKIP: u16 = 771;
pub const ARPHRD_LOOPBACK: u16 = 772;
pub const ARPHRD_LOCALTLK: u16 = 773;
pub const ARPHRD_FDDI: u16 = 774;
pub const ARPHRD_BIF: u16 = 775;
pub const ARPHRD_SIT: u16 = 776;
pub const ARPHRD_IPDDP: u16 = 777;
pub const ARPHRD_IPGRE: u16 = 778;
pub const ARPHRD_PIMREG: u16 = 779;
pub const ARPHRD_HIPPI: u16 = 780;
pub const ARPHRD_ASH: u16 = 781;
pub const ARPHRD_ECONET: u16 = 782;
pub const ARPHRD_IRDA: u16 = 783;
pub const ARPHRD_FCPP: u16 = 784;
pub const ARPHRD_FCAL: u16 = 785;
pub const ARPHRD_FCPL: u16 = 786;
pub const ARPHRD_FCFABRIC: u16 = 787;
pub const ARPHRD_IEEE802_TR: u16 = 800;
pub const ARPHRD_IEEE80211: u16 = 801;
pub const ARPHRD_IEEE80211_PRISM: u16 = 802;
pub const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;
pub const ARPHRD_IEEE802154: u16 = 804;

pub const ARPHRD_VOID: u16 = 0xFFFF;
pub const ARPHRD_NONE: u16 = 0xFFFE;

pub const NDA_UNSPEC: c_ushort = 0;
pub const NDA_DST: c_ushort = 1;
pub const NDA_LLADDR: c_ushort = 2;
pub const NDA_CACHEINFO: c_ushort = 3;
pub const NDA_PROBES: c_ushort = 4;
pub const NDA_VLAN: c_ushort = 5;
pub const NDA_PORT: c_ushort = 6;
pub const NDA_VNI: c_ushort = 7;
pub const NDA_IFINDEX: c_ushort = 8;

pub const AF_NETLINK: c_int = 16;
pub const AF_AX25: c_int = 3;
pub const AF_ATMPVC: c_int = 8;
pub const AF_X25: c_int = 9;
pub const AF_PACKET: c_int = 17;
pub const AF_ALG: c_int = 38;

pub const SOL_NETLINK: c_int = 270;

pub const TCA_UNSPEC: c_ushort = 0;
pub const TCA_KIND: c_ushort = 1;
pub const TCA_OPTIONS: c_ushort = 2;
pub const TCA_STATS: c_ushort = 3;
pub const TCA_XSTATS: c_ushort = 4;
pub const TCA_RATE: c_ushort = 5;
pub const TCA_FCNT: c_ushort = 6;
pub const TCA_STATS2: c_ushort = 7;
pub const TCA_STAB: c_ushort = 8;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
pub const RTM_GETRULE: u16 = 34;
pub const RTM_NEWQDISC: u16 = 36;
pub const RTM_DELQDISC: u16 = 37;
pub const RTM_GETQDISC: u16 = 38;
pub const RTM_NEWTCLASS: u16 = 40;
pub const RTM_DELTCLASS: u16 = 41;
pub const RTM_GETTCLASS: u16 = 42;
pub const RTM_NEWTFILTER: u16 = 44;
pub const RTM_DELTFILTER: u16 = 45;
pub const RTM_GETTFILTER: u16 = 46;
pub const RTM_NEWACTION: u16 = 48;
pub const RTM_DELACTION: u16 = 49;
pub const RTM_GETACTION: u16 = 50;
pub const RTM_NEWPREFIX: u16 = 52;
pub const RTM_GETMULTICAST: u16 = 58;
pub const RTM_GETANYCAST: u16 = 62;
pub const RTM_NEWNEIGHTBL: u16 = 64;
pub const RTM_GETNEIGHTBL: u16 = 66;
pub const RTM_SETNEIGHTBL: u16 = 67;
pub const RTM_NEWNDUSEROPT: u16 = 68;
pub const RTM_NEWADDRLABEL: u16 = 72;
pub const RTM_DELADDRLABEL: u16 = 73;
pub const RTM_GETADDRLABEL: u16 = 74;
pub const RTM_GETDCB: u16 = 78;
pub const RTM_SETDCB: u16 = 79;
pub const RTM_NEWNETCONF: u16 = 80;
pub const RTM_GETNETCONF: u16 = 82;
pub const RTM_NEWMDB: u16 = 84;
pub const RTM_DELMDB: u16 = 85;
pub const RTM_GETMDB: u16 = 86;
pub const RTM_NEWNSID: u16 = 88;
pub const RTM_DELNSID: u16 = 89;
pub const RTM_GETNSID: u16 = 90;

pub const RTM_F_NOTIFY: c_uint = 0x100;
pub const RTM_F_CLONED: c_uint = 0x200;
pub const RTM_F_EQUALIZE: c_uint = 0x400;
pub const RTM_F_PREFIX: c_uint = 0x800;

pub const RTA_UNSPEC: c_ushort = 0;
pub const RTA_DST: c_ushort = 1;
pub const RTA_SRC: c_ushort = 2;
pub const RTA_IIF: c_ushort = 3;
pub const RTA_OIF: c_ushort = 4;
pub const RTA_GATEWAY: c_ushort = 5;
pub const RTA_PRIORITY: c_ushort = 6;
pub const RTA_PREFSRC: c_ushort = 7;
pub const RTA_METRICS: c_ushort = 8;
pub const RTA_MULTIPATH: c_ushort = 9;
pub const RTA_PROTOINFO: c_ushort = 10; // No longer used
pub const RTA_FLOW: c_ushort = 11;
pub const RTA_CACHEINFO: c_ushort = 12;
pub const RTA_SESSION: c_ushort = 13; // No longer used
pub const RTA_MP_ALGO: c_ushort = 14; // No longer used
pub const RTA_TABLE: c_ushort = 15;
pub const RTA_MARK: c_ushort = 16;
pub const RTA_MFC_STATS: c_ushort = 17;

pub const RTN_UNSPEC: c_uchar = 0;
pub const RTN_UNICAST: c_uchar = 1;
pub const RTN_LOCAL: c_uchar = 2;
pub const RTN_BROADCAST: c_uchar = 3;
pub const RTN_ANYCAST: c_uchar = 4;
pub const RTN_MULTICAST: c_uchar = 5;
pub const RTN_BLACKHOLE: c_uchar = 6;
pub const RTN_UNREACHABLE: c_uchar = 7;
pub const RTN_PROHIBIT: c_uchar = 8;
pub const RTN_THROW: c_uchar = 9;
pub const RTN_NAT: c_uchar = 10;
pub const RTN_XRESOLVE: c_uchar = 11;

pub const RTPROT_UNSPEC: c_uchar = 0;
pub const RTPROT_REDIRECT: c_uchar = 1;
pub const RTPROT_KERNEL: c_uchar = 2;
pub const RTPROT_BOOT: c_uchar = 3;
pub const RTPROT_STATIC: c_uchar = 4;

pub const RT_SCOPE_UNIVERSE: c_uchar = 0;
pub const RT_SCOPE_SITE: c_uchar = 200;
pub const RT_SCOPE_LINK: c_uchar = 253;
pub const RT_SCOPE_HOST: c_uchar = 254;
pub const RT_SCOPE_NOWHERE: c_uchar = 255;

pub const RT_TABLE_UNSPEC: c_uchar = 0;
pub const RT_TABLE_COMPAT: c_uchar = 252;
pub const RT_TABLE_DEFAULT: c_uchar = 253;
pub const RT_TABLE_MAIN: c_uchar = 254;
pub const RT_TABLE_LOCAL: c_uchar = 255;

pub const RTMSG_OVERRUN: u32 = NLMSG_OVERRUN as u32;
pub const RTMSG_NEWDEVICE: u32 = 0x11;
pub const RTMSG_DELDEVICE: u32 = 0x12;
pub const RTMSG_NEWROUTE: u32 = 0x21;
pub const RTMSG_DELROUTE: u32 = 0x22;
pub const RTMSG_NEWRULE: u32 = 0x31;
pub const RTMSG_DELRULE: u32 = 0x32;
pub const RTMSG_CONTROL: u32 = 0x40;
pub const RTMSG_AR_FAILED: u32 = 0x51;

pub const MAX_ADDR_LEN: usize = 7;
pub const ARPD_UPDATE: c_ushort = 0x01;
pub const ARPD_LOOKUP: c_ushort = 0x02;
pub const ARPD_FLUSH: c_ushort = 0x03;
pub const ATF_MAGIC: c_int = 0x80;

pub const RTEXT_FILTER_VF: c_int = 1 << 0;
pub const RTEXT_FILTER_BRVLAN: c_int = 1 << 1;
pub const RTEXT_FILTER_BRVLAN_COMPRESSED: c_int = 1 << 2;
pub const RTEXT_FILTER_SKIP_STATS: c_int = 1 << 3;
pub const RTEXT_FILTER_MRP: c_int = 1 << 4;
pub const RTEXT_FILTER_CFM_CONFIG: c_int = 1 << 5;
pub const RTEXT_FILTER_CFM_STATUS: c_int = 1 << 6;

pub const IFLA_UNSPEC: c_ushort = 0;
pub const IFLA_ADDRESS: c_ushort = 1;
pub const IFLA_BROADCAST: c_ushort = 2;
pub const IFLA_IFNAME: c_ushort = 3;
pub const IFLA_MTU: c_ushort = 4;
pub const IFLA_LINK: c_ushort = 5;
pub const IFLA_QDISC: c_ushort = 6;
pub const IFLA_STATS: c_ushort = 7;
pub const IFLA_COST: c_ushort = 8;
pub const IFLA_PRIORITY: c_ushort = 9;
pub const IFLA_MASTER: c_ushort = 10;
pub const IFLA_WIRELESS: c_ushort = 11;
pub const IFLA_PROTINFO: c_ushort = 12;
pub const IFLA_TXQLEN: c_ushort = 13;
pub const IFLA_MAP: c_ushort = 14;
pub const IFLA_WEIGHT: c_ushort = 15;
pub const IFLA_OPERSTATE: c_ushort = 16;
pub const IFLA_LINKMODE: c_ushort = 17;
pub const IFLA_LINKINFO: c_ushort = 18;
pub const IFLA_NET_NS_PID: c_ushort = 19;
pub const IFLA_IFALIAS: c_ushort = 20;
pub const IFLA_NUM_VF: c_ushort = 21;
pub const IFLA_VFINFO_LIST: c_ushort = 22;
pub const IFLA_STATS64: c_ushort = 23;
pub const IFLA_VF_PORTS: c_ushort = 24;
pub const IFLA_PORT_SELF: c_ushort = 25;
pub const IFLA_AF_SPEC: c_ushort = 26;
pub const IFLA_GROUP: c_ushort = 27;
pub const IFLA_NET_NS_FD: c_ushort = 28;
pub const IFLA_EXT_MASK: c_ushort = 29;
pub const IFLA_PROMISCUITY: c_ushort = 30;
pub const IFLA_NUM_TX_QUEUES: c_ushort = 31;
pub const IFLA_NUM_RX_QUEUES: c_ushort = 32;
pub const IFLA_CARRIER: c_ushort = 33;
pub const IFLA_PHYS_PORT_ID: c_ushort = 34;
pub const IFLA_CARRIER_CHANGES: c_ushort = 35;
pub const IFLA_PHYS_SWITCH_ID: c_ushort = 36;
pub const IFLA_LINK_NETNSID: c_ushort = 37;
pub const IFLA_PHYS_PORT_NAME: c_ushort = 38;
pub const IFLA_PROTO_DOWN: c_ushort = 39;
pub const IFLA_GSO_MAX_SEGS: c_ushort = 40;
pub const IFLA_GSO_MAX_SIZE: c_ushort = 41;
pub const IFLA_PAD: c_ushort = 42;
pub const IFLA_XDP: c_ushort = 43;
pub const IFLA_EVENT: c_ushort = 44;
pub const IFLA_NEW_NETNSID: c_ushort = 45;
pub const IFLA_IF_NETNSID: c_ushort = 46;
pub const IFLA_TARGET_NETNSID: c_ushort = IFLA_IF_NETNSID;
pub const IFLA_CARRIER_UP_COUNT: c_ushort = 47;
pub const IFLA_CARRIER_DOWN_COUNT: c_ushort = 48;
pub const IFLA_NEW_IFINDEX: c_ushort = 49;
pub const IFLA_MIN_MTU: c_ushort = 50;
pub const IFLA_MAX_MTU: c_ushort = 51;
pub const IFLA_PROP_LIST: c_ushort = 52;
pub const IFLA_ALT_IFNAME: c_ushort = 53;
pub const IFLA_PERM_ADDRESS: c_ushort = 54;
pub const IFLA_PROTO_DOWN_REASON: c_ushort = 55;
pub const IFLA_PARENT_DEV_NAME: c_ushort = 56;
pub const IFLA_PARENT_DEV_BUS_NAME: c_ushort = 57;
pub const IFLA_GRO_MAX_SIZE: c_ushort = 58;
pub const IFLA_TSO_MAX_SIZE: c_ushort = 59;
pub const IFLA_TSO_MAX_SEGS: c_ushort = 60;
pub const IFLA_ALLMULTI: c_ushort = 61;

pub const IFLA_INFO_UNSPEC: c_ushort = 0;
pub const IFLA_INFO_KIND: c_ushort = 1;
pub const IFLA_INFO_DATA: c_ushort = 2;
pub const IFLA_INFO_XSTATS: c_ushort = 3;
pub const IFLA_INFO_SLAVE_KIND: c_ushort = 4;
pub const IFLA_INFO_SLAVE_DATA: c_ushort = 5;
