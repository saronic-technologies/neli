//! Constants for netfilter related protocols
//!
//! Note that this doesn't cover everything yet, both the list of
//! types and variants in enums will be added over time.

use crate as neli;

use neli_proc_macros::neli_enum;

use crate::compatibility::{
    NFULA_PACKET_HDR, NFULA_MARK, NFULA_TIMESTAMP, NFULA_IFINDEX_INDEV, NFULA_IFINDEX_OUTDEV,
    NFULA_IFINDEX_PHYSINDEV, NFULA_IFINDEX_PHYSOUTDEV, NFULA_HWADDR, NFULA_PAYLOAD, NFULA_PREFIX,
    NFULA_UID, NFULA_SEQ, NFULA_SEQ_GLOBAL, NFULA_GID, NFULA_HWTYPE, NFULA_HWHEADER, NFULA_HWLEN,
    NFULA_CT, NFULA_CT_INFO, NFULA_CFG_CMD, NFULA_CFG_MODE, 
    NFULA_CFG_NLBUFSIZ, NFULA_CFG_TIMEOUT, NFULA_CFG_QTHRESH, NFULA_CFG_FLAGS,
    NFNL_SUBSYS_ULOG, NFULNL_MSG_PACKET, NFULNL_MSG_CONFIG, NFULNL_CFG_CMD_BIND, 
    NFULNL_CFG_CMD_UNBIND, NFULNL_CFG_CMD_PF_BIND, NFULNL_CFG_CMD_PF_UNBIND,
    NFULNL_COPY_NONE, NFULNL_COPY_META, NFULNL_COPY_PACKET,
};

/// Attributes inside a netfilter log packet message.
///
/// These are send by the kernel and describe a logged packet.
#[neli_enum(serialized_type = "u16")]
pub enum NfLogAttr {
    PacketHdr = NFULA_PACKET_HDR as u16,
    Mark = NFULA_MARK as u16,
    Timestamp = NFULA_TIMESTAMP as u16,
    IfindexIndev = NFULA_IFINDEX_INDEV as u16,
    IfindexOutdev = NFULA_IFINDEX_OUTDEV as u16,
    IfindexPhyindev = NFULA_IFINDEX_PHYSINDEV as u16,
    IfindexPhyoutdev = NFULA_IFINDEX_PHYSOUTDEV as u16,
    Hwaddr = NFULA_HWADDR as u16,
    Payload = NFULA_PAYLOAD as u16,
    Prefix = NFULA_PREFIX as u16,
    Uid = NFULA_UID as u16,
    Seq = NFULA_SEQ as u16,
    SeqGlobal = NFULA_SEQ_GLOBAL as u16,
    Gid = NFULA_GID as u16,
    Hwtype = NFULA_HWTYPE as u16,
    Hwheader = NFULA_HWHEADER as u16,
    Hwlen = NFULA_HWLEN as u16,
    Ct = NFULA_CT as u16,
    CtInfo = NFULA_CT_INFO as u16,
}

/// Configuration attributes for netfilter logging.
#[neli_enum(serialized_type = "u16")]
pub enum NfLogCfg {
    Cmd = NFULA_CFG_CMD as u16,
    Mode = NFULA_CFG_MODE as u16,
    NlBufSize = NFULA_CFG_NLBUFSIZ as u16,
    Timeout = NFULA_CFG_TIMEOUT as u16,
    QThresh = NFULA_CFG_QTHRESH as u16,
    Flags = NFULA_CFG_FLAGS as u16,
}

const fn nfnl_msg_type(subsys: u8, msg: u8) -> u16 {
    ((subsys as u16) << 8) | (msg as u16)
}

/// Messages related to the netfilter netlink protocols.
///
/// These appear on the
/// [`NlFamily::Netfilter`][crate::consts::socket::NlFamily::Netfilter]
/// sockets.
#[neli_enum(serialized_type = "u16")]
pub enum NetfilterMsg {
    // TODO: Docs here /// A logged packet, going from kernel to userspace.
    LogPacket = nfnl_msg_type(NFNL_SUBSYS_ULOG as u8, NFULNL_MSG_PACKET as u8),
    // TODO: Docs here /// A logging configuration request, going from userspace to kernel.
    LogConfig = nfnl_msg_type(NFNL_SUBSYS_ULOG as u8, NFULNL_MSG_CONFIG as u8),
}

impl_trait! {
    /// Parameters for the [`NfLogCfg::Cmd`].
    pub LogCfgCmd, u8,
    /// Wrapper that is valid anywhere that accepts a value
    /// implementing the [`LogCfgCmd`] trait
    pub LogCfgCmdWrapper,
    LogCmd
}

/// Command value for the [`NfLogCfg::Cmd`].
#[neli_enum(serialized_type = "u8")]
pub enum LogCmd {
    Bind = NFULNL_CFG_CMD_BIND as u8,
    Unbind = NFULNL_CFG_CMD_UNBIND as u8,
    PfBind = NFULNL_CFG_CMD_PF_BIND as u8,
    PfUnbind = NFULNL_CFG_CMD_PF_UNBIND as u8,
}

/// Copy mode of the logged packets.
#[neli_enum(serialized_type = "u8")]
pub enum LogCopyMode {
    None = NFULNL_COPY_NONE as u8,
    Meta = NFULNL_COPY_META as u8,
    Packet = NFULNL_COPY_PACKET as u8,
}
