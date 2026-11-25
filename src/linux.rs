use crate::{bpf::Firewall, model::Model, process::ProcessKey, procfs};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashSet,
    io,
    net::UdpSocket,
    time::{Duration, Instant},
};

pub const USAGE: &str = concat!(
    "TUI Fire · Monitor y firewall por proceso para Linux\n\n",
    "  sudo tui-fire          Abrir el monitor y el firewall\n",
    "  tui-fire --demo        Explorar la interfaz con datos simulados\n",
    "  sudo tui-fire --check  Probar eBPF con tráfico local IPv4 e IPv6\n",
    "  tui-fire --help        Mostrar esta ayuda\n",
);

pub struct Live(Firewall);

impl Live {
    pub fn new() -> Result<Self> {
        Ok(Self(Firewall::new()?))
    }

    pub fn blocked(&self) -> &HashSet<ProcessKey> {
        &self.0.blocked
    }

    pub fn sample(&mut self, model: &mut Model) -> Result<()> {
        let firewall = &mut self.0;
        let processes = procfs::snapshot().context("leer los procesos de /proc")?;
        firewall.update_sockets(&processes)?;
        let (counters, unassigned) = firewall.sample().context("leer los contadores eBPF")?;
        let now = Instant::now();
        model.update(now, &processes, counters, unassigned);
        for key in model.idle_counters(now) {
            firewall.forget_counter(key)?;
            model.forgot_counter(key);
        }
        Ok(())
    }

    pub fn toggle(&mut self, key: ProcessKey) -> Result<String> {
        let firewall = &mut self.0;
        let block = !firewall.blocked.contains(&key);
        if block && procfs::read_key(key.pid) != Some(key) {
            return Ok(format!("El PID {} ya terminó.", key.pid));
        }
        let processes = procfs::snapshot().context("leer los sockets del proceso")?;
        if block
            && !processes
                .iter()
                .any(|p| p.key == key && p.sockets.is_some())
        {
            return Ok(format!(
                "No se pueden leer los sockets del PID {}.",
                key.pid
            ));
        }
        firewall.set_blocked(key, block)?;
        firewall.update_sockets(&processes)?;
        Ok(format!(
            "PID {} {}",
            key.pid,
            if block { "bloqueado" } else { "desbloqueado" }
        ))
    }
}

fn udp_pair(address: &str) -> io::Result<(UdpSocket, UdpSocket)> {
    let receiver = UdpSocket::bind(address)?;
    receiver.set_read_timeout(Some(Duration::from_millis(400)))?;
    let sender = UdpSocket::bind(address)?;
    sender.connect(receiver.local_addr()?)?;
    Ok((sender, receiver))
}

pub fn check() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "ejecuta la comprobación con sudo"
    );
    let existing = udp_pair("127.0.0.1:0").context("preparar los sockets IPv4 de prueba")?;
    let mut firewall = Firewall::new()?;
    let key = procfs::read_key(std::process::id()).context("identificar el proceso de prueba")?;
    let processes = procfs::snapshot()?;
    firewall.update_sockets(&processes)?;
    check_udp_pair(&mut firewall, key, existing).context("prueba IPv4 con sockets previos")?;
    let new = udp_pair("[::1]:0").context("preparar los sockets IPv6 de prueba")?;
    check_udp_pair(&mut firewall, key, new).context("prueba IPv6 con sockets nuevos")?;
    println!(
        "eBPF activo. Contadores de entrada y salida, bloqueo y desbloqueo verificados en IPv4 e IPv6."
    );
    Ok(())
}

fn check_udp_pair(
    firewall: &mut Firewall,
    key: ProcessKey,
    (sender, receiver): (UdpSocket, UdpSocket),
) -> Result<()> {
    const PAYLOAD: &[u8] = b"tui-fire check";
    let mut buf = [0u8; 64];
    let before = firewall.traffic(key)?;
    sender.send(PAYLOAD)?;
    ensure!(
        receiver.recv(&mut buf)? == PAYLOAD.len(),
        "no se recibió el datagrama de prueba"
    );
    let after = firewall.traffic(key)?;
    ensure!(
        after.rx > before.rx && after.tx > before.tx,
        "eBPF no atribuyó la entrada y la salida al PID de prueba"
    );

    firewall.set_blocked(key, true)?;
    if let Err(error) = sender.send(PAYLOAD) {
        ensure!(
            error.kind() == io::ErrorKind::PermissionDenied,
            "falló el envío bloqueado: {error}"
        );
    }
    let received = receiver.recv(&mut buf);
    ensure!(
        received.is_err_and(|err| matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        )),
        "se recibió tráfico durante el bloqueo"
    );
    ensure!(
        firewall.traffic(key)?.dropped > after.dropped,
        "eBPF no registró el tráfico descartado"
    );

    firewall.set_blocked(key, false)?;
    sender.send(PAYLOAD)?;
    ensure!(
        receiver.recv(&mut buf)? == PAYLOAD.len(),
        "no regresó el tráfico tras desbloquear"
    );
    Ok(())
}
