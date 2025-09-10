use crate as neli;

use std::{io::Cursor, mem::size_of};

use neli_proc_macros::neli_enum;

use crate::{Size, TypeSize};

use crate::{
    compatibility::{
        CTRL_CMD_UNSPEC, CTRL_CMD_NEWFAMILY, CTRL_CMD_DELFAMILY, CTRL_CMD_GETFAMILY,
        CTRL_CMD_NEWOPS, CTRL_CMD_DELOPS, CTRL_CMD_GETOPS, CTRL_CMD_NEWMCAST_GRP,
        CTRL_CMD_DELMCAST_GRP, CTRL_CMD_GETMCAST_GRP, CTRL_ATTR_UNSPEC, CTRL_ATTR_FAMILY_ID,
        CTRL_ATTR_FAMILY_NAME, CTRL_ATTR_VERSION, CTRL_ATTR_HDRSIZE, CTRL_ATTR_MAXATTR,
        CTRL_ATTR_OPS, CTRL_ATTR_MCAST_GROUPS, CTRL_ATTR_MCAST_GRP_UNSPEC,
        CTRL_ATTR_MCAST_GRP_NAME, CTRL_ATTR_MCAST_GRP_ID,
    },
    consts::netfilter::{NfLogAttr, NfLogCfg},
    err::{DeError, SerError},
    FromBytes, ToBytes,
};

impl_trait!(
    /// Trait marking constants valid for use in
    /// [`Genlmsghdr`][crate::genl::Genlmsghdr] field, `cmd`.
    pub Cmd,
    u8,
    /// Wrapper valid for use with all values in the [`Genlmsghdr`]
    /// field, `cmd`
    CmdConsts,
    CtrlCmd
);

/// Values for `cmd` in [`Genlmsghdr`][crate::genl::Genlmsghdr].
#[neli_enum(serialized_type = "u8")]
pub enum CtrlCmd {
    Unspec = CTRL_CMD_UNSPEC as u8,
    Newfamily = CTRL_CMD_NEWFAMILY as u8,
    Delfamily = CTRL_CMD_DELFAMILY as u8,
    Getfamily = CTRL_CMD_GETFAMILY as u8,
    Newops = CTRL_CMD_NEWOPS as u8,
    Delops = CTRL_CMD_DELOPS as u8,
    Getops = CTRL_CMD_GETOPS as u8,
    NewmcastGrp = CTRL_CMD_NEWMCAST_GRP as u8,
    DelmcastGrp = CTRL_CMD_DELMCAST_GRP as u8,
    GetmcastGrp = CTRL_CMD_GETMCAST_GRP as u8,
}

impl_trait!(
    /// Marker trait for types usable in the
    /// [`Nlattr`][crate::genl::Nlattr] field, `nla_type`
    pub NlAttrType,
    u16,
    /// Wrapper that is usable with all values in the
    /// [`Nlattr`][crate::genl::Nlattr] field, `nla_type`.
    pub NlAttrTypeWrapper,
    CtrlAttr,
    CtrlAttrMcastGrp,
    NfLogAttr,
    NfLogCfg,
    Index
);

/// Values for `nla_type` in [`Nlattr`][crate::genl::Nlattr]
#[neli_enum(serialized_type = "u16")]
pub enum CtrlAttr {
    Unspec = CTRL_ATTR_UNSPEC as u16,
    FamilyId = CTRL_ATTR_FAMILY_ID as u16,
    FamilyName = CTRL_ATTR_FAMILY_NAME as u16,
    Version = CTRL_ATTR_VERSION as u16,
    Hdrsize = CTRL_ATTR_HDRSIZE as u16,
    Maxattr = CTRL_ATTR_MAXATTR as u16,
    Ops = CTRL_ATTR_OPS as u16,
    McastGroups = CTRL_ATTR_MCAST_GROUPS as u16,
}

/// Values for `nla_type` in [`Nlattr`][crate::genl::Nlattr]
#[neli_enum(serialized_type = "u16")]
pub enum CtrlAttrMcastGrp {
    Unspec = CTRL_ATTR_MCAST_GRP_UNSPEC as u16,
    Name = CTRL_ATTR_MCAST_GRP_NAME as u16,
    Id = CTRL_ATTR_MCAST_GRP_ID as u16,
}

/// Type representing attribute list types as indices
#[derive(Debug, PartialEq, Eq, Clone, Copy, Size)]
pub struct Index(u16);

impl Index {
    fn is_unrecognized(self) -> bool {
        false
    }
}

impl TypeSize for Index {
    fn type_size() -> usize {
        size_of::<u16>()
    }
}

impl ToBytes for Index {
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        self.0.to_bytes(buffer)
    }
}

impl<'lt> FromBytes<'lt> for Index {
    fn from_bytes(buffer: &mut Cursor<&'lt [u8]>) -> Result<Self, DeError> {
        Ok(Index(u16::from_bytes(buffer)?))
    }
}

impl From<Index> for u16 {
    fn from(i: Index) -> Self {
        i.0
    }
}

impl From<u16> for Index {
    fn from(v: u16) -> Self {
        Index(v)
    }
}
