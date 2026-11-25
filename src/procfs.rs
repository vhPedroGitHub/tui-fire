use crate::process::{Process, ProcessKey};
use std::{fs, io, path::Path};

fn identity(stat: &str) -> Option<(ProcessKey, &str)> {
    let (pid, rest) = stat.split_once(" (")?;
    let (name, rest) = rest.rsplit_once(") ")?;
    // `rest` starts at field 3 (state); starttime is field 22.
    let ticks = rest.split_ascii_whitespace().nth(19)?.parse().ok()?;
    Some((ProcessKey::new(pid.parse().ok()?, ticks), name))
}

pub fn read_key(pid: u32) -> Option<ProcessKey> {
    let stat = fs::read(format!("/proc/{pid}/stat")).ok()?;
    identity(&String::from_utf8_lossy(&stat)).map(|(key, _)| key)
}

pub fn socket_inode(target: &Path) -> Option<u64> {
    target
        .to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn read_process(path: &Path) -> Option<Process> {
    let stat_path = path.join("stat");
    let stat = fs::read(&stat_path).ok()?;
    let stat = String::from_utf8_lossy(&stat);
    let (key, name) = identity(&stat)?;
    let sockets = fs::read_dir(path.join("fd")).ok().map(|entries| {
        entries
            .flatten()
            .filter_map(|fd| socket_inode(&fs::read_link(fd.path()).ok()?))
            .collect()
    });

    // A PID may exit and be reused while its descriptors are being enumerated.
    let latest = fs::read(stat_path).ok()?;
    let latest_key = identity(&String::from_utf8_lossy(&latest))?.0;
    (key == latest_key).then(|| Process {
        key,
        name: name.to_owned(),
        sockets,
    })
}

pub fn snapshot() -> io::Result<Vec<Process>> {
    let mut processes: Vec<_> = fs::read_dir("/proc")?
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .as_encoded_bytes()
                .iter()
                .all(u8::is_ascii_digit)
        })
        .filter_map(|entry| read_process(&entry.path()))
        .collect();
    // Prefer the oldest holder when a socket is shared, e.g. across a fork.
    processes.sort_unstable_by_key(|process| process.key);
    Ok(processes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_process_names_with_parentheses_and_spaces() {
        let stat = "19 (web ) worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 91234";
        assert_eq!(
            identity(stat),
            Some((ProcessKey::new(19, 91234), "web ) worker"))
        );
    }

    #[test]
    fn finds_a_live_socket_by_inode() {
        let (socket, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        use std::os::fd::AsRawFd;
        let pid = std::process::id();
        let path = format!("/proc/{pid}/fd/{}", socket.as_raw_fd());
        let inode = socket_inode(&fs::read_link(path).unwrap()).unwrap();
        let key = read_key(pid).unwrap();
        let processes = snapshot().unwrap();
        let process = processes.iter().find(|process| process.key == key).unwrap();
        assert!(process.sockets.as_ref().unwrap().contains(&inode));
    }
}
