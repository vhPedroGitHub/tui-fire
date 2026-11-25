use std::{
    ffi::c_int,
    io::{self, IsTerminal, Write},
    mem::MaybeUninit,
    os::fd::RawFd,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn stop(_: c_int) {
    STOP.store(true, Ordering::Relaxed);
}

unsafe extern "C" {
    fn wcwidth(ch: libc::wchar_t) -> c_int;
}

pub fn cell_width(ch: char) -> usize {
    unsafe { wcwidth(ch as libc::wchar_t).max(0) as usize }
}

pub fn size() -> (usize, usize) {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_col > 0
        && size.ws_row > 0
    {
        (usize::from(size.ws_col), usize::from(size.ws_row))
    } else {
        (80, 24)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
    Esc,
    Backspace,
    Interrupt,
}

pub struct Terminal {
    original: libc::termios,
    fd: RawFd,
    pending: Vec<u8>,
    escape_at: Option<Instant>,
    signals: [(c_int, libc::sighandler_t); 3],
}

impl Terminal {
    pub fn enter() -> io::Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(io::Error::other("se requiere una terminal interactiva"));
        }
        let fd = libc::STDIN_FILENO;
        let mut original = MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let original = unsafe { original.assume_init() };
        let signals = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP].map(|signal| {
            (signal, unsafe {
                libc::signal(signal, stop as *const () as libc::sighandler_t)
            })
        });
        let terminal = Self {
            original,
            fd,
            pending: Vec::new(),
            escape_at: None,
            signals,
        };
        let mut raw = original;
        unsafe {
            // The UI draws Unicode cells even when launched via sudo with a stripped locale.
            libc::setlocale(libc::LC_CTYPE, c"C.UTF-8".as_ptr());
            libc::cfmakeraw(&mut raw);
        }
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } < 0 {
            return Err(io::Error::last_os_error());
        }
        terminal.draw("\x1b[?1049h\x1b[?25l\x1b[?7l\x1b[2J\x1b[H")?;
        Ok(terminal)
    }

    pub fn draw(&self, frame: &str) -> io::Result<()> {
        let mut output = io::stdout().lock();
        output.write_all(frame.as_bytes())?;
        output.flush()
    }

    pub fn events(&mut self, timeout: Duration) -> io::Result<Vec<Key>> {
        if STOP.load(Ordering::Relaxed) {
            return Ok(vec![Key::Interrupt]);
        }
        let mut fd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let wait = if self.escape_at.is_some() {
            timeout.min(Duration::from_millis(30))
        } else {
            timeout
        };
        let ready = unsafe { libc::poll(&mut fd, 1, wait.as_millis() as c_int) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(Vec::new())
            } else {
                Err(error)
            };
        }
        if fd.revents & libc::POLLIN != 0 {
            let mut buf = [0u8; 4096];
            let count = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if count < 0 {
                let error = io::Error::last_os_error();
                return if error.kind() == io::ErrorKind::Interrupted {
                    Ok(Vec::new())
                } else {
                    Err(error)
                };
            }
            self.pending.extend_from_slice(&buf[..count as usize]);
        } else if fd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(vec![Key::Interrupt]);
        }

        let mut keys = Vec::new();
        let mut offset = 0;
        while offset < self.pending.len() {
            let bytes = &self.pending[offset..];
            let (length, key) = if let Some(event) = parse(bytes) {
                event
            } else if bytes[0] == 27 {
                let start = self.escape_at.get_or_insert_with(Instant::now);
                if start.elapsed() >= Duration::from_millis(30) {
                    (1, Some(Key::Esc))
                } else {
                    break;
                }
            } else {
                break;
            };
            self.escape_at = None;
            offset += length;
            keys.extend(key);
        }
        self.pending.drain(..offset);
        Ok(keys)
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
        let _ = self.draw("\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1049l");
        for (signal, old) in self.signals {
            if old != libc::SIG_ERR {
                unsafe { libc::signal(signal, old) };
            }
        }
    }
}

fn parse(bytes: &[u8]) -> Option<(usize, Option<Key>)> {
    let first = bytes[0];
    let simple = match first {
        3 => Some(Key::Interrupt),
        b'\r' | b'\n' => Some(Key::Enter),
        8 | 127 => Some(Key::Backspace),
        32..=126 => Some(Key::Char(first.into())),
        _ => None,
    };
    if simple.is_some() {
        return Some((1, simple));
    }
    if first == 27 {
        match *bytes.get(1)? {
            b'[' | b'O' => {
                let Some(end) = bytes[2..]
                    .iter()
                    .position(|byte| (0x40..=0x7e).contains(byte))
                    .map(|i| i + 2)
                else {
                    return (bytes.len() > 32).then_some((bytes.len(), None));
                };
                let key = match &bytes[2..=end] {
                    b"A" => Some(Key::Up),
                    b"B" => Some(Key::Down),
                    b"5~" => Some(Key::PageUp),
                    b"6~" => Some(Key::PageDown),
                    b"H" | b"1~" | b"7~" => Some(Key::Home),
                    b"F" | b"4~" | b"8~" => Some(Key::End),
                    _ => None,
                };
                return Some((end + 1, key));
            }
            _ => return Some((1, Some(Key::Esc))),
        }
    }

    let length = match first {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return Some((1, None)),
    };
    if bytes[1..bytes.len().min(length)]
        .iter()
        .any(|byte| byte & 0xc0 != 0x80)
    {
        return Some((1, None));
    }
    let data = bytes.get(..length)?;
    let key = std::str::from_utf8(data)
        .ok()
        .and_then(|value| value.chars().next())
        .filter(|value| !value.is_control())
        .map(Key::Char);
    Some((length, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_arrows_and_utf8_across_reads() {
        assert_eq!(parse(b"\x1b["), None);
        assert_eq!(parse(b"\x1b[Bq"), Some((3, Some(Key::Down))));
        assert_eq!(parse(&[0xc3]), None);
        assert_eq!(parse("ña".as_bytes()), Some((2, Some(Key::Char('ñ')))));
        assert_eq!(parse(&[0xc3, 3]), Some((1, None)));
    }
}
