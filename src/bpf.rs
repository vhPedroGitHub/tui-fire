use crate::process::{Process, ProcessKey, Traffic, comm};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{HashMap, HashSet},
    ffi::{CStr, c_char, c_int, c_uint, c_void},
    fs::File,
    io,
    marker::PhantomData,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr::{self, NonNull},
};

const OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/traffic.bpf.o"));

// These types are opaque in libbpf and are only used behind pointers.
#[repr(C)]
struct BpfObject {
    _private: [u8; 0],
}
#[repr(C)]
struct BpfProgram {
    _private: [u8; 0],
}
#[repr(C)]
struct BpfLink {
    _private: [u8; 0],
}
#[repr(C)]
struct BpfMap {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn bpf_object__open_mem(data: *const u8, size: usize, opts: *const c_void) -> *mut BpfObject;
    fn bpf_object__load(object: *mut BpfObject) -> c_int;
    fn bpf_object__close(object: *mut BpfObject);
    fn bpf_object__find_program_by_name(
        object: *const BpfObject,
        name: *const c_char,
    ) -> *mut BpfProgram;
    fn bpf_object__find_map_by_name(object: *const BpfObject, name: *const c_char) -> *mut BpfMap;
    fn bpf_map__key_size(map: *const BpfMap) -> u32;
    fn bpf_map__value_size(map: *const BpfMap) -> u32;
    fn bpf_map__fd(map: *const BpfMap) -> c_int;
    fn bpf_program__attach(program: *const BpfProgram) -> *mut BpfLink;
    fn bpf_program__fd(program: *const BpfProgram) -> c_int;
    fn bpf_program__expected_attach_type(program: *const BpfProgram) -> c_uint;
    fn bpf_link_create(prog: c_int, target: c_int, kind: c_uint, opts: *const c_void) -> c_int;
    fn bpf_link__destroy(link: *mut BpfLink) -> c_int;
    fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
    fn bpf_map_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_map_delete_elem(fd: c_int, key: *const c_void) -> c_int;
    fn bpf_map_get_next_key(fd: c_int, key: *const c_void, next: *mut c_void) -> c_int;
}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
#[repr(C)]
struct Owner {
    key: ProcessKey,
    name: [u8; 16],
}

impl From<&Process> for Owner {
    fn from(process: &Process) -> Self {
        Self {
            key: process.key,
            name: comm(&process.name),
        }
    }
}

fn result(value: c_int) -> io::Result<c_int> {
    if value < 0 {
        Err(io::Error::from_raw_os_error(-value))
    } else {
        Ok(value)
    }
}

struct Object(NonNull<BpfObject>);

impl Object {
    fn open() -> Result<Self> {
        // libbpf 1.x returns NULL and sets errno on pointer-returning errors.
        let ptr = unsafe { bpf_object__open_mem(OBJECT.as_ptr(), OBJECT.len(), ptr::null()) };
        Ok(Self(
            NonNull::new(ptr).context("no se pudo abrir el objeto eBPF")?,
        ))
    }

    fn load(&mut self) -> Result<()> {
        result(unsafe { bpf_object__load(self.0.as_ptr()) })
            .context("no se pudo cargar eBPF; comprueba BTF y los permisos del kernel")?;
        Ok(())
    }

    fn program(&self, name: &CStr) -> Result<NonNull<BpfProgram>> {
        let program = unsafe { bpf_object__find_program_by_name(self.0.as_ptr(), name.as_ptr()) };
        NonNull::new(program).with_context(|| format!("falta el programa eBPF {name:?}"))
    }

    fn map_descriptor<K, V>(&self, name: &CStr) -> Result<NonNull<BpfMap>> {
        let map = unsafe { bpf_object__find_map_by_name(self.0.as_ptr(), name.as_ptr()) };
        let map = NonNull::new(map).with_context(|| format!("falta el mapa eBPF {name:?}"))?;
        let (key, value) = unsafe {
            (
                bpf_map__key_size(map.as_ptr()),
                bpf_map__value_size(map.as_ptr()),
            )
        };
        ensure!(
            key as usize == size_of::<K>() && value as usize == size_of::<V>(),
            "los tamaños del mapa eBPF {name:?} no coinciden con los de Rust"
        );
        Ok(map)
    }

    fn map<K, V>(&self, name: &CStr) -> Result<Map<K, V>> {
        let descriptor = self.map_descriptor::<K, V>(name)?;
        let fd = result(unsafe { bpf_map__fd(descriptor.as_ptr()) })?;
        Ok(Map {
            fd,
            types: PhantomData,
        })
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        unsafe { bpf_object__close(self.0.as_ptr()) };
    }
}

struct TraceLink(NonNull<BpfLink>);

impl Drop for TraceLink {
    fn drop(&mut self) {
        unsafe { bpf_link__destroy(self.0.as_ptr()) };
    }
}

struct Map<K, V> {
    fd: RawFd,
    types: PhantomData<(K, V)>,
}

impl<K: Copy + Default, V: Copy + Default> Map<K, V> {
    fn get(&self, key: &K) -> io::Result<Option<V>> {
        let mut value = V::default();
        let code = unsafe {
            bpf_map_lookup_elem(
                self.fd,
                ptr::from_ref(key).cast(),
                ptr::from_mut(&mut value).cast(),
            )
        };
        match code {
            0 => Ok(Some(value)),
            code if code == -libc::ENOENT => Ok(None),
            _ => result(code).map(|_| None),
        }
    }

    fn set(&self, key: &K, value: &V) -> io::Result<()> {
        let code = unsafe {
            bpf_map_update_elem(
                self.fd,
                ptr::from_ref(key).cast(),
                ptr::from_ref(value).cast(),
                0,
            )
        };
        result(code).map(|_| ())
    }

    fn delete(&self, key: &K) -> io::Result<()> {
        let code = unsafe { bpf_map_delete_elem(self.fd, ptr::from_ref(key).cast()) };
        if code == -libc::ENOENT {
            Ok(())
        } else {
            result(code).map(|_| ())
        }
    }

    fn entries(&self) -> io::Result<Vec<(K, V)>> {
        let mut entries = Vec::new();
        let mut previous: Option<K> = None;
        loop {
            let mut next = K::default();
            let key = previous.as_ref().map_or(ptr::null(), ptr::from_ref);
            let code = unsafe {
                bpf_map_get_next_key(self.fd, key.cast(), ptr::from_mut(&mut next).cast())
            };
            if code == -libc::ENOENT {
                return Ok(entries);
            }
            result(code)?;
            if let Some(value) = self.get(&next)? {
                entries.push((next, value));
            }
            previous = Some(next);
        }
    }
}

pub struct Firewall {
    // The links are dropped before the object so rules disappear on exit.
    _links: [OwnedFd; 2],
    _trace: TraceLink,
    _object: Object,
    owners: Map<u64, Owner>,
    blocked_sockets: Map<u64, Owner>,
    blocked_pids: Map<ProcessKey, u8>,
    counters: Map<ProcessKey, Traffic>,
    unassigned: Map<u32, Traffic>,
    known_owners: HashMap<u64, Owner>,
    known_blocks: HashMap<u64, Owner>,
    pub blocked: HashSet<ProcessKey>,
}

impl Firewall {
    pub fn new() -> Result<Self> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "se requieren privilegios de administrador; ejecuta con sudo o usa --demo"
        );
        let cgroup = File::open("/sys/fs/cgroup").context("no se pudo abrir el cgroup raíz")?;
        let mut object = Object::open()?;
        object.load()?;

        let program = object.program(c"record_socket")?;
        let link = unsafe { bpf_program__attach(program.as_ptr()) };
        let trace = TraceLink(
            NonNull::new(link)
                .with_context(io::Error::last_os_error)
                .context("no se pudo conectar el registro de sockets")?,
        );

        let attach = |name: &CStr| -> Result<OwnedFd> {
            let program = object.program(name)?;
            let fd = result(unsafe {
                bpf_link_create(
                    bpf_program__fd(program.as_ptr()),
                    cgroup.as_raw_fd(),
                    bpf_program__expected_attach_type(program.as_ptr()),
                    ptr::null(),
                )
            })
            .with_context(|| format!("no se pudo conectar {name:?} al cgroup raíz"))?;
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        };

        Ok(Self {
            _links: [attach(c"inspect_ingress")?, attach(c"inspect_egress")?],
            _trace: trace,
            owners: object.map(c"socket_owners")?,
            blocked_sockets: object.map(c"blocked_sockets")?,
            blocked_pids: object.map(c"blocked_pids")?,
            counters: object.map(c"process_bytes")?,
            unassigned: object.map(c"unassigned_bytes")?,
            _object: object,
            known_owners: HashMap::new(),
            known_blocks: HashMap::new(),
            blocked: HashSet::new(),
        })
    }

    pub fn update_sockets(&mut self, processes: &[Process]) -> Result<()> {
        let live: HashSet<_> = processes.iter().map(|process| process.key).collect();
        let ended: Vec<_> = self.blocked.difference(&live).copied().collect();
        for key in ended {
            self.set_blocked(key, false)?;
        }

        let mut owners = HashMap::new();
        let mut blocks = HashMap::new();
        for process in processes {
            let Some(sockets) = &process.sockets else {
                continue;
            };
            let owner = Owner::from(process);
            let blocked = self.blocked.contains(&owner.key);
            for inode in sockets {
                owners.entry(*inode).or_insert(owner);
                if blocked {
                    blocks.entry(*inode).or_insert(owner);
                }
            }
        }
        sync(&self.blocked_sockets, &mut self.known_blocks, blocks)
            .context("actualizar sockets bloqueados")?;
        sync(&self.owners, &mut self.known_owners, owners)
            .context("actualizar dueños de sockets")?;
        Ok(())
    }

    pub fn set_blocked(&mut self, key: ProcessKey, blocked: bool) -> Result<()> {
        if blocked {
            self.blocked_pids
                .set(&key, &1)
                .context("activar el bloqueo")?;
            self.blocked.insert(key);
        } else {
            self.blocked_pids
                .delete(&key)
                .context("retirar el bloqueo")?;
            self.blocked.remove(&key);
        }
        Ok(())
    }

    pub fn sample(&self) -> Result<(Vec<(ProcessKey, Traffic)>, Traffic)> {
        Ok((
            self.counters.entries()?,
            self.unassigned.get(&0)?.unwrap_or_default(),
        ))
    }

    pub fn forget_counter(&self, key: ProcessKey) -> Result<()> {
        self.counters
            .delete(&key)
            .context("liberar contador de un proceso finalizado")
    }

    pub fn traffic(&self, key: ProcessKey) -> Result<Traffic> {
        Ok(self.counters.get(&key)?.unwrap_or_default())
    }
}

fn sync(
    map: &Map<u64, Owner>,
    known: &mut HashMap<u64, Owner>,
    desired: HashMap<u64, Owner>,
) -> io::Result<()> {
    for inode in known.keys().filter(|inode| !desired.contains_key(inode)) {
        map.delete(inode)?;
    }
    for (inode, owner) in &desired {
        if known.get(inode) != Some(owner) {
            map.set(inode, owner)?;
        }
    }
    *known = desired;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_bpf_object_and_checks_the_rust_map_layouts() -> Result<()> {
        let object = Object::open()?;
        for name in [c"record_socket", c"inspect_ingress", c"inspect_egress"] {
            object.program(name)?;
        }
        object.map_descriptor::<u64, Owner>(c"socket_owners")?;
        object.map_descriptor::<u64, Owner>(c"blocked_sockets")?;
        object.map_descriptor::<ProcessKey, u8>(c"blocked_pids")?;
        object.map_descriptor::<ProcessKey, Traffic>(c"process_bytes")?;
        object.map_descriptor::<u32, Traffic>(c"unassigned_bytes")?;
        Ok(())
    }
}
