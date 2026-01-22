use midnight_zk_stdlib::Relation;

pub mod date;
pub mod filecoin;
pub mod passport;

pub trait Circuit: Relation {
    const K: u32;
}
