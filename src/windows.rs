#[path = "windows/firewall.rs"]
mod firewall;
#[path = "windows/processes.rs"]
mod processes;
#[path = "windows/trace.rs"]
mod trace;

use crate::{
    model::Model,
    process::{Process, ProcessKey},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashSet,
    io,
    net::UdpSocket,
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

pub const USAGE: &str = concat!(
    "TUI Fire · Monitor de tráfico y firewall para Windows\n\n",
    "  tui-fire.exe          Abrir el monitor y el firewall como administrador\n",
    "  tui-fire.exe --demo   Explorar la interfaz con datos simulados\n",
    "  tui-fire.exe --check  Probar la captura ETW y los filtros WFP como administrador\n",
    "  tui-fire.exe --help   Mostrar esta ayuda\n",
);

pub struct Live {
    firewall: firewall::Firewall,
    trace: trace::Trace,
    processes: Vec<Process>,
    blocked: HashSet<ProcessKey>,
}

impl Live {
    pub fn new() -> Result<Self> {
        let processes = processes::snapshot()?;
        let trace = trace::Trace::new(&processes)?;
        let firewall = firewall::Firewall::new()?;
        Ok(Self {
            firewall,
            trace,
            processes,
            blocked: HashSet::new(),
        })
    }

    pub fn blocked(&self) -> &HashSet<ProcessKey> {
        &self.blocked
    }

    pub fn sample(&mut self, model: &mut Model) -> Result<()> {
        self.processes = processes::snapshot()?;
        self.update_blocked();
        let (counters, unassigned) = self.trace.sample(&self.processes)?;
        let now = Instant::now();
        model.update(now, &self.processes, counters, unassigned);
        let idle = model.idle_counters(now);
        self.trace.forget_counters(&idle);
        for key in idle {
            model.forgot_counter(key);
        }
        Ok(())
    }

    fn update_blocked(&mut self) {
        self.blocked = self
            .processes
            .iter()
            .filter_map(|process| {
                self.firewall
                    .blocked(process.executable.as_deref()?)
                    .then_some(process.key)
            })
            .collect();
    }

    pub fn toggle(&mut self, key: ProcessKey) -> Result<String> {
        let (current, path) = processes::image(key.pid, &mut vec![0u16; 32768]);
        if current != key {
            return Ok(format!(
                "El PID {} ya terminó o no está disponible.",
                key.pid
            ));
        }
        let Some(path) = path else {
            return Ok(format!("Ejecutable del PID {} inaccesible.", key.pid));
        };
        let action = match self.firewall.toggle(&path) {
            Ok(true) => "bloqueado",
            Ok(false) => "desbloqueado",
            Err(error) => return Ok(format!("Error de firewall: {error:#}")),
        };
        self.update_blocked();
        Ok(format!("Ejecutable {action} (PID {}).", key.pid))
    }
}

struct Handle(HANDLE);

impl Handle {
    fn new(raw: HANDLE) -> io::Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn status(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

pub fn check() -> Result<()> {
    let mut live = Live::new()?;
    let own = live
        .processes
        .iter()
        .find(|p| p.key.pid == std::process::id())
        .context("identificar el proceso de prueba")?;
    let key = own.key;
    let path = own
        .executable
        .clone()
        .context("obtener el ejecutable de prueba")?;

    for address in ["127.0.0.1:0", "[::1]:0"] {
        let previous = live
            .trace
            .sample(&live.processes)?
            .0
            .into_iter()
            .find(|(pid, _)| *pid == key)
            .map(|(_, data)| data)
            .unwrap_or_default();
        let receiver = UdpSocket::bind(address)?;
        receiver.set_read_timeout(Some(Duration::from_millis(500)))?;
        let sender = UdpSocket::bind(address)?;
        sender.send_to(b"tui-fire check", receiver.local_addr()?)?;
        receiver.recv(&mut [0; 64])?;

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (counters, _) = live.trace.sample(&live.processes)?;
            if counters
                .iter()
                .any(|(pid, data)| *pid == key && data.rx > previous.rx && data.tx > previous.tx)
            {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "ETW no atribuyó la entrada y salida del UDP local ({address})"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
    ensure!(
        live.firewall.toggle(&path)?,
        "no se agregaron los filtros WFP de prueba"
    );
    ensure!(
        !live.firewall.toggle(&path)?,
        "no se retiraron los filtros WFP de prueba"
    );
    println!("Captura ETW local IPv4/IPv6 y alta y baja de filtros WFP verificadas.");
    Ok(())
}
