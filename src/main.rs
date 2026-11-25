#[cfg(target_os = "linux")]
mod bpf;
mod model;
#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(windows, path = "windows.rs")]
mod platform;
mod process;
#[cfg(target_os = "linux")]
mod procfs;
#[cfg_attr(windows, path = "windows/terminal.rs")]
mod terminal;
mod ui;

use anyhow::{Result, bail};
use model::Model;
use platform::Live;
use process::{Process, ProcessKey, Traffic};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use terminal::Terminal;
use ui::{Action, Ui};

fn main() {
    if let Err(error) = run() {
        eprintln!("tui-fire: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => interactive(Source::Live(Box::new(Live::new()?))),
        [arg] if arg == "--demo" => interactive(Source::Demo(Demo::new())),
        [arg] if arg == "--check" => platform::check(),
        [arg] if arg == "--help" || arg == "-h" => {
            print!("{}", platform::USAGE);
            Ok(())
        }
        [arg] if arg == "--version" || arg == "-V" => {
            println!("tui-fire {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => bail!("argumento desconocido. Usa --help para ver las opciones"),
    }
}

enum Source {
    Live(Box<Live>),
    Demo(Demo),
}

impl Source {
    fn blocked(&self) -> &HashSet<ProcessKey> {
        match self {
            Self::Live(live) => live.blocked(),
            Self::Demo(demo) => &demo.blocked,
        }
    }

    fn sample(&mut self, model: &mut Model) -> Result<()> {
        match self {
            Self::Live(live) => live.sample(model),
            Self::Demo(demo) => {
                demo.sample(model);
                Ok(())
            }
        }
    }

    fn toggle(&mut self, key: ProcessKey) -> Result<String> {
        match self {
            Self::Live(live) => live.toggle(key),
            Self::Demo(demo) => {
                let blocked = if demo.blocked.remove(&key) {
                    false
                } else {
                    demo.blocked.insert(key);
                    true
                };
                Ok(format!(
                    "PID {} {}",
                    key.pid,
                    if blocked { "bloqueado" } else { "desbloqueado" }
                ))
            }
        }
    }
}

fn interactive(mut source: Source) -> Result<()> {
    const INTERVAL: Duration = Duration::from_secs(1);
    let mut terminal = Terminal::enter()?;
    let mut model = Model::default();
    let mut ui = Ui::default();
    let demo = matches!(source, Source::Demo(_));
    let mut size = terminal::size();
    let mut sample_at = Instant::now();
    let mut redraw = true;
    loop {
        if Instant::now() >= sample_at {
            source.sample(&mut model)?;
            sample_at = Instant::now() + INTERVAL;
            redraw = true;
        }
        let dimensions = terminal::size();
        if size != dimensions {
            size = dimensions;
            redraw = true;
        }
        if redraw {
            terminal.draw(&ui.render(&model, source.blocked(), demo, size.0, size.1))?;
            redraw = false;
        }

        let wait = sample_at
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100));
        for key in terminal.events(wait)? {
            match ui.handle(key, &model, source.blocked(), size.1) {
                Action::Continue => (),
                Action::Quit => return Ok(()),
                Action::Toggle(key) => ui.message(source.toggle(key)?),
            }
            redraw = true;
        }
    }
}

struct Demo {
    processes: Vec<Process>,
    counters: Vec<(ProcessKey, Traffic)>,
    blocked: HashSet<ProcessKey>,
    tick: u64,
}

impl Demo {
    fn new() -> Self {
        let names = [
            "firefox",
            "steam",
            "syncthing",
            "spotify",
            "podman",
            "ssh",
            "systemd-resolved",
            "tailscaled",
            "NetworkManager",
            "cupsd",
            "systemd",
            "zsh",
            "nvim",
            "pipewire",
            "waybar",
            "Hyprland",
        ];
        let processes: Vec<_> = names
            .into_iter()
            .enumerate()
            .map(|(index, name)| Process {
                key: ProcessKey::new(1215 + index as u32 * 77, 1000 + index as u64),
                name: name.into(),
                #[cfg(windows)]
                executable: None,
                sockets: Some(
                    (0..index % 12)
                        .map(|socket| (index * 50 + socket) as u64)
                        .collect(),
                ),
            })
            .collect();
        let counters = processes
            .iter()
            .map(|process| (process.key, Traffic::default()))
            .collect();
        Self {
            processes,
            counters,
            blocked: HashSet::new(),
            tick: 0,
        }
    }

    fn sample(&mut self, model: &mut Model) {
        let rates = [
            (1_840_000, 80_000),
            (320_000, 21_000),
            (62_000, 450_000),
            (41_000, 2_100),
            (12_000, 4_500),
            (4_300, 7_200),
            (1_400, 920),
            (950, 2_300),
            (140, 380),
        ];
        for ((key, traffic), (index, (rx, tx))) in
            self.counters.iter_mut().zip(rates.into_iter().enumerate())
        {
            let scale = 76 + (self.tick * (index as u64 + 11) * 7 + 23) % 49;
            let (rx, tx) = (rx * scale / 100, tx * scale / 100);
            if self.blocked.contains(key) {
                traffic.dropped += rx + tx;
            } else {
                traffic.rx += rx;
                traffic.tx += tx;
            }
        }
        self.tick += 1;
        model.update(
            Instant::now(),
            &self.processes,
            self.counters.clone(),
            Traffic::default(),
        );
    }
}
