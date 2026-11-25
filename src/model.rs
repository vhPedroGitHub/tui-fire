use crate::process::{Process, ProcessKey, Traffic};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

#[derive(Copy, Clone, Default)]
pub struct Bytes {
    pub rx: u64,
    pub tx: u64,
    pub dropped: u64,
}

impl Bytes {
    pub fn total(self) -> u64 {
        self.rx.saturating_add(self.tx)
    }

    pub fn add(self, other: Self) -> Self {
        Self {
            rx: self.rx.saturating_add(other.rx),
            tx: self.tx.saturating_add(other.tx),
            dropped: self.dropped.saturating_add(other.dropped),
        }
    }

    fn since(self, earlier: Self) -> Self {
        Self {
            rx: self.rx.saturating_sub(earlier.rx),
            tx: self.tx.saturating_sub(earlier.tx),
            dropped: self.dropped.saturating_sub(earlier.dropped),
        }
    }

    fn per_second(self, seconds: f64) -> Self {
        Self {
            rx: (self.rx as f64 / seconds) as u64,
            tx: (self.tx as f64 / seconds) as u64,
            dropped: (self.dropped as f64 / seconds) as u64,
        }
    }
}

impl From<Traffic> for Bytes {
    fn from(data: Traffic) -> Self {
        Self {
            rx: data.rx,
            tx: data.tx,
            dropped: data.dropped,
        }
    }
}

pub struct Row {
    pub key: ProcessKey,
    pub name: String,
    pub alive: bool,
    pub can_block: bool,
    pub sockets: Option<usize>,
    pub total: Bytes,
    pub rate: Bytes,
    last: Bytes,
    last_used: Instant,
    has_counter: bool,
}

impl Row {
    fn new(key: ProcessKey, name: String, now: Instant) -> Self {
        Self {
            key,
            name,
            alive: false,
            can_block: false,
            sockets: None,
            total: Bytes::default(),
            rate: Bytes::default(),
            last: Bytes::default(),
            last_used: now,
            has_counter: false,
        }
    }

    pub fn has_traffic(&self) -> bool {
        self.total.total() > 0 || self.total.dropped > 0
    }
}

#[derive(Default)]
pub struct Model {
    pub rows: HashMap<ProcessKey, Row>,
    previous: Option<Instant>,
    unassigned: Bytes,
    pub unassigned_rate: Bytes,
}

impl Model {
    pub fn update(
        &mut self,
        now: Instant,
        processes: &[Process],
        counters: Vec<(ProcessKey, Traffic)>,
        unassigned: Traffic,
    ) {
        let seconds = self.previous.replace(now).map_or(1.0, |previous| {
            now.duration_since(previous).as_secs_f64().max(0.01)
        });
        for row in self.rows.values_mut() {
            row.alive = false;
            row.rate = Bytes::default();
        }
        for process in processes {
            let row = self
                .rows
                .entry(process.key)
                .or_insert_with(|| Row::new(process.key, String::new(), now));
            row.alive = true;
            row.can_block = process.can_block();
            row.name.clone_from(&process.name);
            row.sockets = process.sockets.as_ref().map(HashSet::len);
            row.last_used = now;
        }
        for (key, traffic) in counters {
            let row = self.rows.entry(key).or_insert_with(|| {
                let name = traffic
                    .name
                    .split(|byte| *byte == 0)
                    .next()
                    .unwrap_or_default();
                let name = if name.is_empty() {
                    "?".into()
                } else {
                    String::from_utf8_lossy(name).into_owned()
                };
                Row::new(key, name, now)
            });
            let bytes = Bytes::from(traffic);
            let change = bytes.since(row.last);
            if change.total() > 0 || change.dropped > 0 {
                row.last_used = now;
            }
            row.has_counter = true;
            row.last = bytes;
            row.total = row.total.add(change);
            row.rate = change.per_second(seconds);
        }
        self.rows
            .retain(|_, row| row.alive || row.has_traffic() || row.has_counter);
        let unassigned = Bytes::from(unassigned);
        self.unassigned_rate = unassigned.since(self.unassigned).per_second(seconds);
        self.unassigned = unassigned;
    }

    pub fn idle_counters(&self, now: Instant) -> Vec<ProcessKey> {
        self.rows
            .values()
            .filter(|row| {
                row.has_counter
                    && !row.alive
                    && now.duration_since(row.last_used) > Duration::from_secs(60)
            })
            .map(|row| row.key)
            .collect()
    }

    pub fn forgot_counter(&mut self, key: ProcessKey) {
        if let Some(row) = self.rows.get_mut(&key) {
            row.has_counter = false;
            row.last = Bytes::default();
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Sort {
    Name,
    Speed,
    Total,
    Rx,
    Tx,
    Pid,
}

impl Sort {
    pub const ALL: [Self; 6] = [
        Self::Name,
        Self::Speed,
        Self::Total,
        Self::Rx,
        Self::Tx,
        Self::Pid,
    ];

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|mode| *mode == self).unwrap()
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Nombre",
            Self::Speed => "Velocidad",
            Self::Total => "Acumulado",
            Self::Rx => "Bajada",
            Self::Tx => "Subida",
            Self::Pid => "PID",
        }
    }

    pub fn descending(self) -> bool {
        !matches!(self, Self::Name | Self::Pid)
    }

    pub fn sort(self, rows: &mut [&Row], descending: bool) {
        rows.sort_unstable_by(|a, b| {
            let order = match self {
                Self::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                Self::Speed => a.rate.total().cmp(&b.rate.total()),
                Self::Total => a.total.total().cmp(&b.total.total()),
                Self::Rx => a.rate.rx.cmp(&b.rate.rx),
                Self::Tx => a.rate.tx.cmp(&b.rate.tx),
                Self::Pid => a.key.pid.cmp(&b.key.pid),
            };
            let order = if descending { order.reverse() } else { order };
            order
                .then_with(|| a.key.pid.cmp(&b.key.pid))
                .then_with(|| a.key.cmp(&b.key))
        });
    }
}

#[derive(Copy, Clone)]
pub enum Filter {
    All,
    Traffic,
    Active,
    Blocked,
}

impl Filter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Traffic,
            Self::Traffic => Self::Active,
            Self::Active => Self::Blocked,
            Self::Blocked => Self::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "Todos",
            Self::Traffic => "Con tráfico",
            Self::Active => "En curso",
            Self::Blocked => "Bloqueados",
        }
    }

    pub fn includes(self, row: &Row, blocked: bool) -> bool {
        match self {
            Self::All => true,
            Self::Traffic => row.has_traffic(),
            Self::Active => row.rate.total() > 0 || row.rate.dropped > 0,
            Self::Blocked => blocked,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_totals_and_isolates_reused_pids() {
        let mut model = Model::default();
        let first = ProcessKey::new(13, 1);
        let second = ProcessKey::new(13, 2);
        let now = Instant::now();
        let tick = Duration::from_secs(1);
        let received = |rx| Traffic {
            rx,
            ..Traffic::default()
        };
        model.update(now, &[], vec![(first, received(250))], Traffic::default());
        model.update(
            now + 2 * tick,
            &[],
            vec![(first, received(450)), (second, received(800))],
            Traffic::default(),
        );
        assert_eq!(model.rows[&first].rate.rx, 100);
        assert_eq!(model.rows[&first].total.rx, 450);
        assert_eq!(model.rows[&second].total.rx, 800);
        model.forgot_counter(first);
        model.update(
            now + 3 * tick,
            &[],
            vec![(first, received(70))],
            Traffic::default(),
        );
        assert_eq!(model.rows[&first].total.rx, 520);
    }
}
