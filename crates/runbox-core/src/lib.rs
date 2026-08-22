//! runbox-core: everything Runbox does that isn't the setuid privilege
//! drop itself (that logic lives only in runbox-helper).

pub mod acl;
pub mod archive;
pub mod config;
pub mod diff;
pub mod identity;
pub mod lock;
pub mod pf;
pub mod seatbelt;
pub mod setup;
