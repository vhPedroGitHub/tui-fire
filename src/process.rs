use std::collections::HashSet;

#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(C)]
pub struct ProcessKey {
    pub start_ticks: u64,
    pub pid: u32,
    reserved: u32,
}

impl ProcessKey {
    pub const fn new(pid: u32, start_ticks: u64) -> Self {
        Self {
            start_ticks,
            pid,
            reserved: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Process {
    pub key: ProcessKey,
    pub name: String,
    pub sockets: Option<HashSet<u64>>,
    #[cfg(windows)]
    pub executable: Option<Vec<u16>>,
}

impl Process {
    pub fn can_block(&self) -> bool {
        #[cfg(windows)]
        if self.executable.is_some() {
            return true;
        }
        self.sockets.is_some()
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Traffic {
    pub rx: u64,
    pub tx: u64,
    pub dropped: u64,
    pub name: [u8; 16],
}

pub fn comm(name: &str) -> [u8; 16] {
    let mut bytes = [0; 16];
    let mut len = name.len().min(bytes.len() - 1);
    while !name.is_char_boundary(len) {
        len -= 1;
    }
    bytes[..len].copy_from_slice(&name.as_bytes()[..len]);
    bytes
}
