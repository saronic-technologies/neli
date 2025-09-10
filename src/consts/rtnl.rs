use crate as neli;

use neli_proc_macros::neli_enum;
use crate::compatibility::osx::*;

/// Internet address families
#[neli_enum(serialized_type = "libc::c_uchar")]
pub enum Af {
    Inet = libc::AF_INET as libc::c_uchar,
    Inet6 = libc::AF_INET6 as libc::c_uchar,
}

/// General address families for sockets
#[neli_enum(serialized_type = "u8")]
pub enum RtAddrFamily {
    Unspecified = libc::AF_UNSPEC as u8,
    UnixOrLocal = libc::AF_UNIX as u8,
    Inet = libc::AF_INET as u8,
    Inet6 = libc::AF_INET6 as u8,
    Ipx = libc::AF_IPX as u8,
    Netlink = AF_NETLINK as u8,
    X25 = AF_X25 as u8,
    Ax25 = AF_AX25 as u8,
    Atmpvc = AF_ATMPVC as u8,
    Appletalk = libc::AF_APPLETALK as u8,
    Packet = AF_PACKET as u8,
    Alg = AF_ALG as u8,
}

/// Interface address flags
#[neli_enum(serialized_type = "u8")]
pub enum IfaF {
    Secondary = IFA_F_SECONDARY as u8,
    Temporary = IFA_F_TEMPORARY as u8,
    Nodad = IFA_F_NODAD as u8,
    Optimistic = IFA_F_OPTIMISTIC as u8,
    Dadfailed = IFA_F_DADFAILED as u8,
    Homeaddress = IFA_F_HOMEADDRESS as u8,
    Deprecated = IFA_F_DEPRECATED as u8,
    Tentative = IFA_F_TENTATIVE as u8,
    Permanent = IFA_F_PERMANENT as u8,
}

/// `rtm_type`
/// The results of a lookup from a route table
#[neli_enum(serialized_type = "libc::c_uchar")]
pub enum Rtn {
    Unspec = RTN_UNSPEC,
    Unicast = RTN_UNICAST,
    Local = RTN_LOCAL,
    Broadcast = RTN_BROADCAST,
    Anycast = RTN_ANYCAST,
    Multicast = RTN_MULTICAST,
    Blackhole = RTN_BLACKHOLE,
    Unreachable = RTN_UNREACHABLE,
    Prohibit = RTN_PROHIBIT,
    Throw = RTN_THROW,
    Nat = RTN_NAT,
    Xresolve = RTN_XRESOLVE,
}

/// `rtm_protocol`
/// The origins of routes that are defined in the kernel
#[neli_enum(serialized_type = "libc::c_uchar")]
pub enum Rtprot {
    Unspec = RTPROT_UNSPEC,
    Redirect = RTPROT_REDIRECT,
    Kernel = RTPROT_KERNEL,
    Boot = RTPROT_BOOT,
    Static = RTPROT_STATIC,
}

/// `rtm_scope`
/// The distance between destinations
#[neli_enum(serialized_type = "libc::c_uchar")]
pub enum RtScope {
    Universe = RT_SCOPE_UNIVERSE,
    Site = RT_SCOPE_SITE,
    Link = RT_SCOPE_LINK,
    Host = RT_SCOPE_HOST,
    Nowhere = RT_SCOPE_NOWHERE,
}

/// `rt_class_t`
/// Reserved route table identifiers
#[neli_enum(serialized_type = "libc::c_uchar")]
pub enum RtTable {
    Unspec = RT_TABLE_UNSPEC,
    Compat = RT_TABLE_COMPAT,
    Default = RT_TABLE_DEFAULT,
    Main = RT_TABLE_MAIN,
    Local = RT_TABLE_LOCAL,
}

/// `rtm_flags`
/// Flags for rtnetlink messages
#[neli_enum(serialized_type = "libc::c_uint")]
pub enum RtmF {
    Notify = RTM_F_NOTIFY,
    Cloned = RTM_F_CLONED,
    Equalize = RTM_F_EQUALIZE,
    Prefix = RTM_F_PREFIX,

    #[cfg(target_env = "gnu")]
    LookupTable = libc::RTM_F_LOOKUP_TABLE,
    #[cfg(target_env = "gnu")]
    FibMatch = libc::RTM_F_FIB_MATCH,
}

/// Arp neighbor cache entry states
#[neli_enum(serialized_type = "u16")]
pub enum Nud {
    None = NUD_NONE,
    Incomplete = NUD_INCOMPLETE,
    Reachable = NUD_REACHABLE,
    Stale = NUD_STALE,
    Delay = NUD_DELAY,
    Probe = NUD_PROBE,
    Failed = NUD_FAILED,
    Noarp = NUD_NOARP,
    Permanent = NUD_PERMANENT,
}

/// Arp neighbor cache entry flags
#[neli_enum(serialized_type = "u8")]
pub enum Ntf {
    Use = NTF_USE,
    Self_ = NTF_SELF,
    Master = NTF_MASTER,
    Proxy = NTF_PROXY,
    #[cfg(target_env = "gnu")]
    ExtLearned = libc::NTF_EXT_LEARNED,
    #[cfg(target_env = "gnu")]
    Offloaded = libc::NTF_OFFLOADED,
    Router = NTF_ROUTER,
}

impl_trait!(
    /// Marker trait for [`Rtattr`][crate::rtnl::Rtattr] field,
    /// `rta_type`.
    pub RtaType,
    libc::c_ushort,
    /// Wrapper that is usable for all values in
    /// [`Rtattr`][crate::rtnl::Rtattr] field, `rta_type`
    pub RtaTypeWrapper,
    Ifla,
    Ifa,
    Rta,
    Tca,
    Nda,
    IflaInfo
);

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values are interface information message attributes. Used with
/// [`Ifinfomsg`][crate::rtnl::Ifinfomsg].
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Ifla {
    Unspec = IFLA_UNSPEC,
    Address = IFLA_ADDRESS,
    Broadcast = IFLA_BROADCAST,
    Ifname = IFLA_IFNAME,
    Mtu = IFLA_MTU,
    Link = IFLA_LINK,
    Qdisc = IFLA_QDISC,
    Stats = IFLA_STATS,
    Cost = IFLA_COST,
    Priority = IFLA_PRIORITY,
    Master = IFLA_MASTER,
    Wireless = IFLA_WIRELESS,
    Protinfo = IFLA_PROTINFO,
    Txqlen = IFLA_TXQLEN,
    Map = IFLA_MAP,
    Weight = IFLA_WEIGHT,
    Operstate = IFLA_OPERSTATE,
    Linkmode = IFLA_LINKMODE,
    Linkinfo = IFLA_LINKINFO,
    NetNsPid = IFLA_NET_NS_PID,
    Ifalias = IFLA_IFALIAS,
    NumVf = IFLA_NUM_VF,
    VfinfoList = IFLA_VFINFO_LIST,
    Stats64 = IFLA_STATS64,
    VfPorts = IFLA_VF_PORTS,
    PortSelf = IFLA_PORT_SELF,
    AfSpec = IFLA_AF_SPEC,
    Group = IFLA_GROUP,
    NetNsFd = IFLA_NET_NS_FD,
    ExtMask = IFLA_EXT_MASK,
    Promiscuity = IFLA_PROMISCUITY,
    NumTxQueues = IFLA_NUM_TX_QUEUES,
    NumRxQueues = IFLA_NUM_RX_QUEUES,
    Carrier = IFLA_CARRIER,
    PhysPortId = IFLA_PHYS_PORT_ID,
    CarrierChanges = IFLA_CARRIER_CHANGES,
    PhysSwitchId = IFLA_PHYS_SWITCH_ID,
    LinkNetnsid = IFLA_LINK_NETNSID,
    PhysPortName = IFLA_PHYS_PORT_NAME,
    ProtoDown = IFLA_PROTO_DOWN,
    GsoMaxSegs = IFLA_GSO_MAX_SEGS,
    GsoMaxSize = IFLA_GSO_MAX_SIZE,
    Pad = IFLA_PAD,
    Xdp = IFLA_XDP,
    Event = IFLA_EVENT,
    NewNetnsid = IFLA_NEW_NETNSID,
    IfNetnsid = IFLA_IF_NETNSID,
    CarrierUpCount = IFLA_CARRIER_UP_COUNT,
    CarrierDownCount = IFLA_CARRIER_DOWN_COUNT,
    NewIfindex = IFLA_NEW_IFINDEX,
    MinMtu = IFLA_MIN_MTU,
    MaxMtu = IFLA_MAX_MTU,
    PropList = IFLA_PROP_LIST,
    AltIfname = IFLA_ALT_IFNAME,
    PermAddress = IFLA_PERM_ADDRESS,
    ProtoDownReason = IFLA_PROTO_DOWN_REASON,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values are nested attributes to IFLA_LINKMODE.
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum IflaInfo {
    Unspec = IFLA_INFO_UNSPEC,
    Kind = IFLA_INFO_KIND,
    Data = IFLA_INFO_DATA,
    Xstats = IFLA_INFO_XSTATS,
    SlaveKind = IFLA_INFO_SLAVE_KIND,
    SlaveData = IFLA_INFO_SLAVE_DATA,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values are interface address message attributes. Used with
/// [`Ifaddrmsg`][crate::rtnl::Ifaddrmsg].
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Ifa {
    Unspec = IFA_UNSPEC,
    Address = IFA_ADDRESS,
    Local = IFA_LOCAL,
    Label = IFA_LABEL,
    Broadcast = IFA_BROADCAST,
    Anycast = IFA_ANYCAST,
    Cacheinfo = IFA_CACHEINFO,
    Multicast = IFA_MULTICAST,
    Flags = IFA_FLAGS,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values are routing message attributes. Used with
/// [`Rtmsg`][crate::rtnl::Rtmsg].
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Rta {
    Unspec = RTA_UNSPEC,
    Dst = RTA_DST,
    Src = RTA_SRC,
    Iif = RTA_IIF,
    Oif = RTA_OIF,
    Gateway = RTA_GATEWAY,
    Priority = RTA_PRIORITY,
    Prefsrc = RTA_PREFSRC,
    Metrics = RTA_METRICS,
    Multipath = RTA_MULTIPATH,
    Protoinfo = RTA_PROTOINFO, // no longer used in Linux
    Flow = RTA_FLOW,
    Cacheinfo = RTA_CACHEINFO,
    Session = RTA_SESSION, // no longer used in Linux
    MpAlgo = RTA_MP_ALGO,  // no longer used in Linux
    Table = RTA_TABLE,
    Mark = RTA_MARK,
    MfcStats = RTA_MFC_STATS,
    #[cfg(target_env = "gnu")]
    Via = libc::RTA_VIA,
    #[cfg(target_env = "gnu")]
    Newdst = libc::RTA_NEWDST,
    #[cfg(target_env = "gnu")]
    Pref = libc::RTA_PREF,
    #[cfg(target_env = "gnu")]
    EncapType = libc::RTA_ENCAP_TYPE,
    #[cfg(target_env = "gnu")]
    Encap = libc::RTA_ENCAP,
    #[cfg(target_env = "gnu")]
    Expires = libc::RTA_EXPIRES,
    #[cfg(target_env = "gnu")]
    Pad = libc::RTA_PAD,
    #[cfg(target_env = "gnu")]
    Uid = libc::RTA_UID,
    #[cfg(target_env = "gnu")]
    TtlPropagate = libc::RTA_TTL_PROPAGATE,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values specify queuing discipline attributes. Used with
/// [`Tcmsg`][crate::rtnl::Tcmsg].
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Tca {
    Unspec = TCA_UNSPEC,
    Kind = TCA_KIND,
    Options = TCA_OPTIONS,
    Stats = TCA_STATS,
    Xstats = TCA_XSTATS,
    Rate = TCA_RATE,
    Fcnt = TCA_FCNT,
    Stats2 = TCA_STATS2,
    Stab = TCA_STAB,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values specify neighbor table attributes
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Nda {
    Unspec = NDA_UNSPEC,
    Dst = NDA_DST,
    Lladdr = NDA_LLADDR,
    Cacheinfo = NDA_CACHEINFO,
    Probes = NDA_PROBES,
    Vlan = NDA_VLAN,
    Port = NDA_PORT,
    Vni = NDA_VNI,
    Ifindex = NDA_IFINDEX,
    #[cfg(target_env = "gnu")]
    Master = libc::NDA_MASTER,
    #[cfg(target_env = "gnu")]
    LinkNetnsid = libc::NDA_LINK_NETNSID,
    #[cfg(target_env = "gnu")]
    SrcVni = libc::NDA_SRC_VNI,
}

/// Interface types
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Arphrd {
    Netrom = ARPHRD_NETROM,
    Ether = ARPHRD_ETHER,
    Eether = ARPHRD_EETHER,
    AX25 = ARPHRD_AX25,
    Pronet = ARPHRD_PRONET,
    Chaos = ARPHRD_CHAOS,
    Ieee802 = ARPHRD_IEEE802,
    Arcnet = ARPHRD_ARCNET,
    Appletlk = ARPHRD_APPLETLK,
    Dlci = ARPHRD_DLCI,
    Atm = ARPHRD_APPLETLK,
    Metricom = ARPHRD_METRICOM,
    Ieee1394 = ARPHRD_IEEE1394,
    Eui64 = ARPHRD_EUI64,
    Infiniband = ARPHRD_INFINIBAND,

    Loopback = ARPHRD_LOOPBACK,

    // Possibly more types here - need to look into ARP more
    Void = ARPHRD_VOID,
    None = ARPHRD_NONE,
}

/// Values for `ifi_flags` in
/// [`Ifinfomsg`][crate::rtnl::Ifinfomsg].
#[neli_enum(serialized_type = "libc::c_uint")]
pub enum Iff {
    Up = libc::IFF_UP as libc::c_uint,
    Broadcast = libc::IFF_BROADCAST as libc::c_uint,
    Debug = libc::IFF_DEBUG as libc::c_uint,
    Loopback = libc::IFF_LOOPBACK as libc::c_uint,
    Pointopoint = libc::IFF_POINTOPOINT as libc::c_uint,
    Running = libc::IFF_RUNNING as libc::c_uint,
    Noarp = libc::IFF_NOARP as libc::c_uint,
    Promisc = libc::IFF_PROMISC as libc::c_uint,
    Notrailers = libc::IFF_NOTRAILERS as libc::c_uint,
    Allmulti = libc::IFF_ALLMULTI as libc::c_uint,
    Master = IFF_MASTER as libc::c_uint,
    Slave = IFF_SLAVE as libc::c_uint,
    Multicast = libc::IFF_MULTICAST as libc::c_uint,
    Portsel = IFF_PORTSEL as libc::c_uint,
    Automedia = IFF_AUTOMEDIA as libc::c_uint,
    Dynamic = IFF_DYNAMIC as libc::c_uint,
    LowerUp = IFF_LOWER_UP as libc::c_uint,
    Dormant = IFF_DORMANT as libc::c_uint,
    Echo = IFF_ECHO as libc::c_uint,
    // Possibly more types here - need to look into private flags for interfaces
}

impl_flags!(
    #[allow(missing_docs)]
    pub IffFlags, Iff, libc::c_uint
);

impl_flags!(
    #[allow(missing_docs)]
    pub IfaFFlags, IfaF, libc::c_uchar
);

impl_flags!(
    #[allow(missing_docs)]
    pub RtmFFlags, RtmF, libc::c_uint
);
impl_flags!(
    #[allow(missing_docs)]
    pub NudFlags, Nud, u16
);
impl_flags!(
    #[allow(missing_docs)]
    pub NtfFlags, Ntf, u8
);

/// rtnetlink-related values for `nl_type` in
/// [`Nlmsghdr`][crate::nl::Nlmsghdr].
#[neli_enum(serialized_type = "u16")]
pub enum Rtm {
    Newlink = RTM_NEWLINK,
    Dellink = RTM_DELLINK,
    Getlink = RTM_GETLINK,
    Setlink = RTM_SETLINK,
    Newaddr = RTM_NEWADDR,
    Deladdr = RTM_DELADDR,
    Getaddr = RTM_GETADDR,
    Newroute = RTM_NEWROUTE,
    Delroute = RTM_DELROUTE,
    Getroute = RTM_GETROUTE,
    Newneigh = RTM_NEWNEIGH,
    Delneigh = RTM_DELNEIGH,
    Getneigh = RTM_GETNEIGH,
    Newrule = RTM_NEWRULE,
    Delrule = RTM_DELRULE,
    Getrule = RTM_GETRULE,
    Newqdisc = RTM_NEWQDISC,
    Delqdisc = RTM_DELQDISC,
    Getqdisc = RTM_GETQDISC,
    Newtclass = RTM_NEWTCLASS,
    Deltclass = RTM_DELTCLASS,
    Gettclass = RTM_GETTCLASS,
    Newtfilter = RTM_NEWTFILTER,
    Deltfilter = RTM_DELTFILTER,
    Gettfilter = RTM_GETTFILTER,
    Newaction = RTM_NEWACTION,
    Delaction = RTM_DELACTION,
    Getaction = RTM_GETACTION,
    Newprefix = RTM_NEWPREFIX,
    Getmulticast = RTM_GETMULTICAST,
    Getanycast = RTM_GETANYCAST,
    Newneightbl = RTM_NEWNEIGHTBL,
    Getneightbl = RTM_GETNEIGHTBL,
    Setneightbl = RTM_SETNEIGHTBL,
    Newnduseropt = RTM_NEWNDUSEROPT,
    Newaddrlabel = RTM_NEWADDRLABEL,
    Deladdrlabel = RTM_DELADDRLABEL,
    Getaddrlabel = RTM_GETADDRLABEL,
    Getdcb = RTM_GETDCB,
    Setdcb = RTM_SETDCB,
    Newnetconf = RTM_NEWNETCONF,
    Getnetconf = RTM_GETNETCONF,
    Newmdb = RTM_NEWMDB,
    Delmdb = RTM_DELMDB,
    Getmdb = RTM_GETMDB,
    Newnsid = RTM_NEWNSID,
    Delnsid = RTM_DELNSID,
    Getnsid = RTM_GETNSID,
}
