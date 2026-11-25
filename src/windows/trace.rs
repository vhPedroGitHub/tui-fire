use super::{Handle, status};
use crate::process::{Process, ProcessKey, Traffic, comm};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashMap,
    io, ptr, slice,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_ALREADY_EXISTS, GetLastError},
        System::{Diagnostics::Etw::*, Threading::CreateMutexW},
    },
    core::{GUID, w},
};

const NAME: *const u16 = w!("TUI Fire Network");
const SESSION_GUID: GUID = GUID::from_u128(0x1a97d481_2006_4225_a05d_aba277686058);

#[repr(C)]
struct Properties {
    etw: EVENT_TRACE_PROPERTIES,
    logger_name: [u16; 64],
}

impl Properties {
    fn new() -> Self {
        let mut etw = EVENT_TRACE_PROPERTIES {
            BufferSize: 64,
            MaximumBuffers: 128,
            LogFileMode: EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE,
            FlushTimer: 1,
            EnableFlags: EVENT_TRACE_FLAG_NETWORK_TCPIP | EVENT_TRACE_FLAG_NO_SYSCONFIG,
            LoggerNameOffset: std::mem::offset_of!(Self, logger_name) as u32,
            ..Default::default()
        };
        etw.Wnode.BufferSize = size_of::<Self>() as u32;
        etw.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        etw.Wnode.Guid = SESSION_GUID;
        etw.Wnode.ClientContext = 1; // QPC, converted to FILETIME by ProcessTrace.
        Self {
            etw,
            logger_name: [0; 64],
        }
    }
}

struct Session {
    control: CONTROLTRACE_HANDLE,
    _exclusive: Handle,
}

impl Session {
    fn new() -> Result<Self> {
        let raw = unsafe { CreateMutexW(ptr::null(), 0, w!("Global\\TuiFireNetworkTrace")) };
        let last_error = unsafe { GetLastError() };
        let exclusive = Handle::new(raw).context("reservar la sesión de red de TUI Fire")?;
        ensure!(
            last_error != ERROR_ALREADY_EXISTS,
            "TUI Fire ya está capturando en otra ventana"
        );

        let mut control = CONTROLTRACE_HANDLE { Value: 0 };
        let mut properties = Properties::new();
        let mut code = unsafe { StartTraceW(&mut control, NAME, &mut properties.etw) };
        if code == ERROR_ALREADY_EXISTS {
            // The mutex is free, so a matching session was left by a terminated process.
            let mut previous = Properties::new();
            let by_name = CONTROLTRACE_HANDLE { Value: 0 };
            status(unsafe {
                ControlTraceW(by_name, NAME, &mut previous.etw, EVENT_TRACE_CONTROL_QUERY)
            })
            .context("consultar la sesión ETW anterior")?;
            ensure!(
                same_guid(previous.etw.Wnode.Guid, SESSION_GUID),
                "el nombre de sesión ETW está ocupado"
            );
            status(unsafe {
                ControlTraceW(by_name, NAME, &mut previous.etw, EVENT_TRACE_CONTROL_STOP)
            })
            .context("cerrar la captura ETW anterior")?;
            properties = Properties::new();
            code = unsafe { StartTraceW(&mut control, NAME, &mut properties.etw) };
        }
        status(code)
            .context("iniciar la captura de red ETW; abre la terminal como administrador")?;
        Ok(Self {
            control,
            _exclusive: exclusive,
        })
    }

    fn stop(&mut self) {
        if self.control.Value != 0 {
            let mut properties = Properties::new();
            unsafe {
                ControlTraceW(
                    self.control,
                    ptr::null(),
                    &mut properties.etw,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            self.control.Value = 0;
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct Trace {
    session: Session,
    consumer: PROCESSTRACE_HANDLE,
    worker: Option<JoinHandle<u32>>,
    data: Arc<Mutex<Data>>,
}

impl Trace {
    pub fn new(processes: &[Process]) -> Result<Self> {
        let session = Session::new()?;
        let data = Arc::new(Mutex::new(Data {
            identities: identities(processes),
            ..Data::default()
        }));
        let mut log = EVENT_TRACE_LOGFILEW {
            LoggerName: NAME.cast_mut(),
            Anonymous1: EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME,
            },
            Anonymous2: EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(event),
            },
            Context: Arc::as_ptr(&data).cast_mut().cast(),
            ..Default::default()
        };
        let consumer = unsafe { OpenTraceW(&mut log) };
        if consumer.Value == u64::MAX {
            return Err(io::Error::last_os_error()).context("abrir el lector de eventos ETW");
        }
        let mut trace = Self {
            session,
            consumer,
            worker: None,
            data,
        };
        let callback_data = Arc::clone(&trace.data);
        trace.worker = Some(
            thread::Builder::new()
                .name("tui-fire-etw".into())
                .spawn(move || {
                    let _callback_data = callback_data;
                    unsafe { ProcessTrace(&consumer, 1, ptr::null(), ptr::null()) }
                })
                .context("iniciar el lector de eventos ETW")?,
        );
        Ok(trace)
    }

    pub fn sample(
        &mut self,
        processes: &[Process],
    ) -> Result<(Vec<(ProcessKey, Traffic)>, Traffic)> {
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            let code = self
                .worker
                .take()
                .unwrap()
                .join()
                .map_err(|_| anyhow::anyhow!("falló el hilo de ETW"))?;
            status(code).context("leer eventos de red de Windows")?;
            bail!("la captura de red de Windows se cerró");
        }
        let identities = identities(processes);
        let mut data = self
            .data
            .lock()
            .map_err(|_| anyhow::anyhow!("falló el almacenamiento de eventos ETW"))?;
        data.identities = identities;
        for (pid, pending) in std::mem::take(&mut data.pending) {
            data.record(pid, pending.first, pending.rx, pending.tx, false);
        }
        Ok((
            data.counters
                .iter()
                .map(|(&key, &traffic)| (key, traffic))
                .collect(),
            data.unassigned,
        ))
    }

    pub fn forget_counters(&self, keys: &[ProcessKey]) {
        if !keys.is_empty()
            && let Ok(mut data) = self.data.lock()
        {
            for key in keys {
                data.counters.remove(key);
            }
        }
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        self.session.stop();
        unsafe { CloseTrace(self.consumer) };
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Copy, Clone)]
struct Identity {
    key: ProcessKey,
    name: [u8; 16],
}

fn identities(processes: &[Process]) -> HashMap<u32, Identity> {
    processes
        .iter()
        .map(|p| {
            (
                p.key.pid,
                Identity {
                    key: p.key,
                    name: comm(&p.name),
                },
            )
        })
        .collect()
}

struct Pending {
    first: u64,
    rx: u64,
    tx: u64,
}

#[derive(Default)]
struct Data {
    identities: HashMap<u32, Identity>,
    counters: HashMap<ProcessKey, Traffic>,
    pending: HashMap<u32, Pending>,
    unassigned: Traffic,
}

impl Data {
    fn record(&mut self, pid: u32, time: u64, rx: u64, tx: u64, defer: bool) {
        let identity = self
            .identities
            .get(&pid)
            .filter(|id| time >= id.key.start_ticks);
        let traffic = if let Some(id) = identity {
            self.counters.entry(id.key).or_insert_with(|| Traffic {
                name: id.name,
                ..Traffic::default()
            })
        } else if pid != 0 && defer && !self.identities.contains_key(&pid) {
            let pending = self.pending.entry(pid).or_insert(Pending {
                first: time,
                rx: 0,
                tx: 0,
            });
            pending.first = pending.first.min(time);
            pending.rx = pending.rx.saturating_add(rx);
            pending.tx = pending.tx.saturating_add(tx);
            return;
        } else {
            &mut self.unassigned
        };
        traffic.rx = traffic.rx.saturating_add(rx);
        traffic.tx = traffic.tx.saturating_add(tx);
    }
}

unsafe extern "system" fn event(record: *mut EVENT_RECORD) {
    // ETW owns the record/payload for this callback. Trace keeps its context alive until ProcessTrace returns.
    let record = unsafe { &*record };
    let header = record.EventHeader;
    if record.UserDataLength < 8 || record.UserData.is_null() || record.UserContext.is_null() {
        return;
    }
    let data = unsafe { slice::from_raw_parts(record.UserData.cast::<u8>(), 8) };
    let Some((pid, rx, tx)) = decode(
        header.ProviderId,
        header.EventDescriptor.Version,
        header.EventDescriptor.Opcode,
        data,
    ) else {
        return;
    };
    let state = unsafe { &*record.UserContext.cast::<Mutex<Data>>() };
    if let Ok(mut state) = state.lock() {
        state.record(pid, header.TimeStamp as u64, rx, tx, true);
    }
}

fn decode(provider: GUID, version: u8, opcode: u8, data: &[u8]) -> Option<(u32, u64, u64)> {
    let tcp = same_guid(provider, TcpIpGuid);
    if version < 2 || (!tcp && !same_guid(provider, UdpIpGuid)) {
        return None;
    }
    // The TCP and UDP v2 send/receive payloads (v4 and v6) start with PID and size.
    let pid = u32::from_le_bytes(data.get(..4)?.try_into().ok()?);
    let size = u64::from(u32::from_le_bytes(data.get(4..8)?.try_into().ok()?));
    match opcode {
        10 | 26 => Some((pid, 0, size)),
        11 | 27 => Some((pid, size, 0)),
        14 | 30 if tcp => Some((pid, 0, size)), // TCP retransmit.
        _ => None,
    }
}

fn same_guid(a: GUID, b: GUID) -> bool {
    (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_payload_pid_and_byte_count_for_ipv4_and_ipv6() {
        let payload = [42, 0, 0, 0, 220, 5, 0, 0];
        assert_eq!(decode(TcpIpGuid, 2, 26, &payload), Some((42, 0, 1500)));
        assert_eq!(decode(UdpIpGuid, 2, 11, &payload), Some((42, 1500, 0)));
        assert_eq!(decode(TcpIpGuid, 2, 30, &payload), Some((42, 0, 1500)));
        assert_eq!(decode(TcpIpGuid, 2, 18, &payload), None);
        assert_eq!(decode(UdpIpGuid, 1, 10, &payload), None);
        assert_eq!(decode(UdpIpGuid, 2, 10, &payload[..4]), None);
    }
}
