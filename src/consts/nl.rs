use crate as neli;

use neli_proc_macros::neli_enum;

use crate::{
    compatibility::{
        NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE, NLMSG_OVERRUN, GENL_ID_CTRL,
        NLM_F_REQUEST, NLM_F_MULTI, NLM_F_ACK, NLM_F_ECHO, NLM_F_DUMP_INTR, NLM_F_DUMP_FILTERED,
        NLM_F_ROOT, NLM_F_MATCH, NLM_F_ATOMIC, NLM_F_DUMP, NLM_F_REPLACE, NLM_F_EXCL,
        NLM_F_CREATE, NLM_F_APPEND,
    },
    consts::{netfilter::NetfilterMsg, rtnl::Rtm},
};

impl_trait!(
    /// Trait marking constants valid for use in
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr] field, `nl_type`.
    pub NlType,
    u16,
    /// Wrapper that is usable with all values in
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr] field,
    /// `nl_type`.
    pub NlTypeWrapper,
    Nlmsg,
    GenlId,
    Rtm,
    NetfilterMsg
);

/// Values for `nl_type` in [`Nlmsghdr`][crate::nl::Nlmsghdr]
#[neli_enum(serialized_type = "u16")]
pub enum Nlmsg {
    Noop = NLMSG_NOOP as u16,
    Error = NLMSG_ERROR as u16,
    Done = NLMSG_DONE as u16,
    Overrun = NLMSG_OVERRUN as u16,
}

/// Values for `nl_type` in [`Nlmsghdr`][crate::nl::Nlmsghdr]
#[neli_enum(serialized_type = "u16")]
pub enum GenlId {
    Ctrl = GENL_ID_CTRL as u16,
    #[cfg(target_env = "gnu")]
    VfsDquot = libc::GENL_ID_VFS_DQUOT as u16,
    #[cfg(target_env = "gnu")]
    Pmcraid = libc::GENL_ID_PMCRAID as u16,
}

/// Values for `nl_flags` in [`Nlmsghdr`][crate::nl::Nlmsghdr]
#[neli_enum(serialized_type = "u16")]
pub enum NlmF {
    /// This flag is required for all kernel requests
    Request = NLM_F_REQUEST as u16,
    Multi = NLM_F_MULTI as u16,
    Ack = NLM_F_ACK as u16,
    Echo = NLM_F_ECHO as u16,
    DumpIntr = NLM_F_DUMP_INTR as u16,
    DumpFiltered = NLM_F_DUMP_FILTERED as u16,
    Root = NLM_F_ROOT as u16,
    Match = NLM_F_MATCH as u16,
    Atomic = NLM_F_ATOMIC as u16,
    Dump = NLM_F_DUMP as u16,
    Replace = NLM_F_REPLACE as u16,
    Excl = NLM_F_EXCL as u16,
    Create = NLM_F_CREATE as u16,
    Append = NLM_F_APPEND as u16,
}

impl_flags!(
    #[allow(missing_docs)]
    pub NlmFFlags, NlmF, u16
);
