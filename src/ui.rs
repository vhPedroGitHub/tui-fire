use crate::{
    model::{Bytes, Filter, Model, Row, Sort},
    process::ProcessKey,
    terminal::{Key, cell_width},
};
use std::{collections::HashSet, fmt::Write};

const RESET: &str = "\x1b[0m";
const BACKGROUND: &str = "\x1b[48;2;16;24;37m";
const BAR: &str = "\x1b[48;2;24;37;53m";
const SELECTED: &str = "\x1b[48;2;33;63;72m";
const VERY_LIGHT: &str = "\x1b[38;2;229;240;245m";
const MUTED: &str = "\x1b[38;2;151;176;193m";
const MINT: &str = "\x1b[38;2;112;232;192m";
const BLUE: &str = "\x1b[38;2;147;197;253m";
const ORANGE: &str = "\x1b[38;2;255;174;135m";
const BOLD: &str = "\x1b[1m";

pub struct Ui {
    sort: Sort,
    descending: bool,
    filter: Filter,
    query: String,
    previous_query: Option<String>,
    index: usize,
    scroll: usize,
    help: bool,
    message: Option<String>,
}

pub enum Action {
    Continue,
    Quit,
    Toggle(ProcessKey),
}

impl Default for Ui {
    fn default() -> Self {
        Self {
            sort: Sort::Speed,
            descending: true,
            filter: Filter::All,
            query: String::new(),
            previous_query: None,
            index: 0,
            scroll: 0,
            help: false,
            message: None,
        }
    }
}

impl Ui {
    fn rows<'a>(&self, model: &'a Model, blocked: &HashSet<ProcessKey>) -> Vec<&'a Row> {
        let query = self.query.trim().to_lowercase();
        let mut rows: Vec<_> = model
            .rows
            .values()
            .filter(|row| {
                self.filter.includes(row, blocked.contains(&row.key))
                    && (query.is_empty()
                        || row.name.to_lowercase().contains(&query)
                        || row.key.pid.to_string() == query)
            })
            .collect();
        self.sort.sort(&mut rows, self.descending);
        rows
    }

    fn select(&mut self, row_count: usize, index: usize, page: usize) {
        self.index = index.min(row_count.saturating_sub(1));
        self.scroll = self.scroll.clamp(
            self.index.saturating_add(1).saturating_sub(page.max(1)),
            self.index,
        );
        self.scroll = self.scroll.min(row_count.saturating_sub(page));
    }

    fn sort_by(&mut self, sort: Sort) {
        self.sort = sort;
        self.descending = sort.descending();
        self.index = 0;
        self.scroll = 0;
    }

    pub fn message(&mut self, text: String) {
        self.message = Some(text);
    }

    pub fn handle(
        &mut self,
        key: Key,
        model: &Model,
        blocked: &HashSet<ProcessKey>,
        height: usize,
    ) -> Action {
        if key == Key::Interrupt {
            return Action::Quit;
        }
        if self.help {
            self.help = false;
            return if key == Key::Char('q') {
                Action::Quit
            } else {
                Action::Continue
            };
        }
        if self.previous_query.is_some() {
            match key {
                Key::Enter => self.previous_query = None,
                Key::Esc => self.query = self.previous_query.take().unwrap_or_default(),
                Key::Backspace => {
                    self.query.pop();
                }
                Key::Char(ch) if self.query.chars().count() < 128 => self.query.push(ch),
                _ => (),
            }
            self.index = 0;
            return Action::Continue;
        }

        self.message = None;
        let page = height.saturating_sub(7);
        let rows = self.rows(model, blocked);
        let row_count = rows.len();
        self.select(row_count, self.index, page);
        match key {
            Key::Char('q') | Key::Esc => return Action::Quit,
            Key::Char('?') => self.help = true,
            Key::Char('/') => self.previous_query = Some(self.query.clone()),
            Key::Char('f') => {
                self.filter = self.filter.next();
                self.index = 0;
            }
            Key::Char('s') => self.sort_by(Sort::ALL[(self.sort.index() + 1) % Sort::ALL.len()]),
            Key::Char(digit @ '1'..='6') => {
                self.sort_by(Sort::ALL[(digit as usize) - ('1' as usize)])
            }
            Key::Char('r') => {
                self.descending = !self.descending;
                self.index = 0;
            }
            Key::Up | Key::Char('k') => self.select(row_count, self.index.saturating_sub(1), page),
            Key::Down | Key::Char('j') => {
                self.select(row_count, self.index.saturating_add(1), page)
            }
            Key::PageUp => self.select(row_count, self.index.saturating_sub(page), page),
            Key::PageDown => self.select(row_count, self.index.saturating_add(page), page),
            Key::Home => self.select(row_count, 0, page),
            Key::End => self.select(row_count, row_count.saturating_sub(1), page),
            Key::Char('b') => {
                if let Some(row) = rows.get(self.index).filter(|row| row.alive) {
                    return Action::Toggle(row.key);
                }
                self.message("Selecciona un proceso en ejecución.".into());
            }
            _ => (),
        }
        Action::Continue
    }

    pub fn render(
        &mut self,
        model: &Model,
        blocked: &HashSet<ProcessKey>,
        demo: bool,
        width: usize,
        height: usize,
    ) -> String {
        let mut frame = Frame {
            text: String::with_capacity(width * height * 2),
            width,
            line: 1,
        };
        frame.line(
            BAR,
            &[
                (MINT, "  TUI FIRE  "),
                (
                    VERY_LIGHT,
                    if demo {
                        "  Demo · datos simulados"
                    } else {
                        "  Tráfico de red por proceso"
                    },
                ),
            ],
        );
        if self.help {
            self.render_help(&mut frame, height);
            return frame.text;
        }
        if width < 56 || height < 9 {
            frame.line(
                BACKGROUND,
                &[(MUTED, "  Amplía la terminal (56 × 9 mínimo).")],
            );
            frame.fill(height);
            return frame.text;
        }

        let page = height - 7;
        let rows = self.rows(model, blocked);
        self.select(rows.len(), self.index, page);
        let rate = model
            .rows
            .values()
            .fold(Bytes::default(), |sum, row| sum.add(row.rate));
        let rx = format!("↓ {}", speed(rate.rx));
        let tx = format!("  ↑ {}", speed(rate.tx));
        let num_blocked = format!("  ·  {} bloqueados", blocked.len());
        let unassigned = model.unassigned_rate.total();
        let other = if unassigned > 0 {
            format!("  ·  Sin atribuir {}", speed(unassigned))
        } else {
            String::new()
        };
        frame.line(
            BACKGROUND,
            &[
                (MUTED, "  "),
                (MINT, &rx),
                (BLUE, &tx),
                (MUTED, &num_blocked),
                (MUTED, &other),
            ],
        );
        let sort = format!(
            "  {} {}",
            self.sort.label(),
            if self.descending { '↓' } else { '↑' }
        );
        let query = format!(
            "  / {}{}",
            visible(&self.query),
            if self.previous_query.is_some() {
                "▏"
            } else {
                ""
            }
        );
        let filter = format!("  ·  {} ({})", self.filter.label(), rows.len());
        frame.line(
            BACKGROUND,
            &[(VERY_LIGHT, &sort), (MUTED, &filter), (MINT, &query)],
        );

        let columns = Columns::new(width);
        let header = columns.format(
            " ",
            "PID",
            "PROCESO",
            "BAJADA/s",
            "SUBIDA/s",
            "ACUMULADO",
            "ESTADO",
        );
        frame.line(BAR, &[(BOLD, ""), (MUTED, &header)]);
        for index in self.scroll..self.scroll + page {
            let Some(row) = rows.get(index) else {
                if rows.is_empty() && index == 0 {
                    frame.line(BACKGROUND, &[(MUTED, "  No hay procesos que coincidan.")]);
                } else {
                    frame.line(BACKGROUND, &[]);
                }
                continue;
            };
            let selected = index == self.index;
            let blocked = blocked.contains(&row.key);
            let state = if blocked {
                "Bloqueado"
            } else if !row.alive {
                "Finalizado"
            } else if !row.can_block {
                "Sin acceso"
            } else {
                "Permitido"
            };
            let state_color = if blocked {
                ORANGE
            } else if row.alive && row.rate.total() > 0 {
                MINT
            } else {
                MUTED
            };
            let stem = columns.format(
                if selected { "▸" } else { " " },
                &row.key.pid.to_string(),
                &visible(&row.name),
                &quantity(row.rate.rx),
                &quantity(row.rate.tx),
                &quantity(row.total.total()),
                "",
            );
            let bg = if selected { SELECTED } else { BACKGROUND };
            let text_color = if !selected && !row.alive {
                MUTED
            } else {
                VERY_LIGHT
            };
            if columns.live_state {
                let prefix = stem.trim_end_matches(' ');
                let spacer = " ".repeat(columns.state_start().saturating_sub(width_of(prefix)));
                frame.line(
                    bg,
                    &[
                        (text_color, prefix),
                        (state_color, &spacer),
                        (state_color, state),
                    ],
                );
            } else {
                frame.line(bg, &[(if blocked { ORANGE } else { text_color }, &stem)]);
            }
        }

        let detail = if let Some(row) = rows.get(self.index) {
            let summary = format!(
                "  PID {}  ·  ↓ {}   ↑ {}",
                row.key.pid,
                quantity(row.total.rx),
                quantity(row.total.tx)
            );
            #[cfg(windows)]
            let summary = format!("{summary}  ·  Bloqueo por ejecutable");
            #[cfg(target_os = "linux")]
            let summary = {
                let sockets = row
                    .sockets
                    .filter(|_| row.alive)
                    .map_or("—".into(), |sockets| sockets.to_string());
                format!(
                    "{summary}  ·  Descartado {}  ·  Sockets {sockets}",
                    quantity(row.total.dropped)
                )
            };
            summary
        } else {
            String::new()
        };
        frame.line(BAR, &[(MUTED, &detail)]);
        let guidance = if self.previous_query.is_some() {
            "  Escribe un nombre o PID · Intro aplica · Esc cancela"
        } else {
            "  ↑↓ mover   / buscar   f filtrar   s ordenar   r invertir"
        };
        frame.line(BACKGROUND, &[(VERY_LIGHT, guidance)]);
        let toggle = if rows
            .get(self.index)
            .is_some_and(|row| blocked.contains(&row.key))
        {
            "  b desbloquear"
        } else {
            "  b bloquear"
        };
        frame.line(
            BACKGROUND,
            &[
                (MINT, toggle),
                (VERY_LIGHT, "   ? ayuda   q salir"),
                (ORANGE, if self.message.is_some() { "    " } else { "" }),
                (ORANGE, self.message.as_deref().unwrap_or("")),
            ],
        );
        frame.text
    }

    fn render_help(&self, frame: &mut Frame, height: usize) {
        let lines = [
            "  Teclas y filtros",
            "  ↑ / ↓, j / k   Seleccionar proceso",
            "  AvPág, RePág   Recorrer la lista por páginas",
            "  Inicio, Fin    Ir al primer o último proceso",
            "  /              Buscar por nombre o PID exacto",
            "  f              Todos, con tráfico, en curso, bloqueados",
            "  s              Siguiente criterio de ordenación",
            "  1–6            Nombre, velocidad, total, bajada, subida, PID",
            "  r              Invertir ascendente / descendente",
            if cfg!(windows) {
                "  b              Bloquear o desbloquear todas las instancias del ejecutable"
            } else {
                "  b              Bloquear o desbloquear la entrada y la salida"
            },
            "  q              Salir y retirar los bloqueos de esta sesión",
            "",
            "  Acumulado suma la entrada y la salida desde que abriste la TUI.",
            "  Pulsa cualquier tecla para volver.",
        ];
        for line in lines.iter().take(height.saturating_sub(1)) {
            frame.line(BACKGROUND, &[(VERY_LIGHT, line)]);
        }
        frame.fill(height);
    }
}

struct Columns {
    name: usize,
    live_state: bool,
}

impl Columns {
    fn new(width: usize) -> Self {
        let live_state = width >= 70;
        let name = width - if live_state { 59 } else { 47 };
        Self { name, live_state }
    }

    fn state_start(&self) -> usize {
        49 + self.name
    }

    #[allow(clippy::too_many_arguments)]
    fn format(
        &self,
        marker: &str,
        pid: &str,
        name: &str,
        rx: &str,
        tx: &str,
        total: &str,
        state: &str,
    ) -> String {
        let mut text = format!(
            " {marker} {:>7}  {}  {:>10} {:>10} {:>10} ",
            pid,
            field(name, self.name),
            rx,
            tx,
            total
        );
        if self.live_state {
            write!(text, "  {state}").unwrap();
        }
        text
    }
}

struct Frame {
    text: String,
    line: usize,
    width: usize,
}

impl Frame {
    fn line(&mut self, background: &str, parts: &[(&str, &str)]) {
        write!(self.text, "\x1b[{};1H{RESET}{background}", self.line).unwrap();
        let mut remaining = self.width;
        for (color, content) in parts {
            self.text.push_str(color);
            for ch in content.chars() {
                let w = cell_width(ch);
                if w > remaining {
                    break;
                }
                self.text.push(ch);
                remaining -= w;
            }
            if remaining == 0 {
                break;
            }
        }
        self.text.push_str("\x1b[K");
        self.text.push_str(RESET);
        self.line += 1;
    }

    fn fill(&mut self, height: usize) {
        while self.line <= height {
            self.line(BACKGROUND, &[]);
        }
    }
}

fn quantity(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn speed(bytes: u64) -> String {
    format!("{}/s", quantity(bytes))
}

fn width_of(text: &str) -> usize {
    text.chars().map(cell_width).sum()
}

fn visible(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { '�' } else { ch })
        .collect()
}

fn field(text: &str, width: usize) -> String {
    let truncated = width_of(text) > width;
    let limit = width.saturating_sub(usize::from(truncated));
    let mut length = 0;
    let mut field = String::new();
    for ch in text.chars() {
        let w = cell_width(ch);
        if length + w > limit {
            break;
        }
        length += w;
        field.push(ch);
    }
    if truncated {
        field.push('…');
        length += 1;
    }
    field.push_str(&" ".repeat(width.saturating_sub(length)));
    field
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{Process, Traffic};
    use std::time::{Duration, Instant};

    #[test]
    fn keeps_the_visible_row_selected_when_the_download_order_changes() {
        let processes: Vec<_> = (101..=104)
            .map(|pid| Process {
                key: ProcessKey::new(pid, 1),
                name: format!("proceso-{pid}"),
                sockets: Some(HashSet::new()),
                #[cfg(windows)]
                executable: None,
            })
            .collect();
        let counters = |downloads: [u64; 4]| {
            processes
                .iter()
                .zip(downloads)
                .map(|(process, rx)| {
                    (
                        process.key,
                        Traffic {
                            rx,
                            ..Traffic::default()
                        },
                    )
                })
                .collect()
        };
        let mut ui = Ui::default();
        let mut model = Model::default();
        let blocked = HashSet::new();
        let now = Instant::now();
        let height = 9;

        model.update(
            now,
            &processes,
            counters([200, 150, 100, 50]),
            Traffic::default(),
        );
        ui.handle(Key::Char('4'), &model, &blocked, height);
        ui.handle(Key::Down, &model, &blocked, height);
        assert!(
            ui.render(&model, &blocked, false, 100, height)
                .contains("PID 102")
        );

        model.update(
            now + Duration::from_secs(1),
            &processes,
            counters([400, 150, 200, 100]),
            Traffic::default(),
        );
        let frame = ui.render(&model, &blocked, false, 100, height);
        assert_eq!((ui.index, ui.scroll), (1, 0));
        assert!(frame.contains("PID 103"));
        assert!(
            matches!(ui.handle(Key::Char('b'), &model, &blocked, height), Action::Toggle(key) if key == processes[2].key)
        );
    }
}
