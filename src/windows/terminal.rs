use std::{
    io::{self, IsTerminal, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use unicode_width::UnicodeWidthChar;
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{Console::*, Threading::WaitForSingleObject},
    UI::Input::KeyboardAndMouse::{
        VK_BACK, VK_DOWN, VK_END, VK_ESCAPE, VK_HOME, VK_NEXT, VK_PRIOR, VK_RETURN, VK_UP,
    },
};

static STOP: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn stop(event: u32) -> i32 {
    if matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        STOP.store(true, Ordering::Relaxed);
        1
    } else {
        0
    }
}

pub fn cell_width(ch: char) -> usize {
    ch.width().unwrap_or(0)
}

pub fn size() -> (usize, usize) {
    let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    if unsafe { GetConsoleScreenBufferInfo(output, &mut info) } == 0 {
        return (80, 24);
    }
    let window = info.srWindow;
    (
        (i32::from(window.Right) - i32::from(window.Left) + 1).max(1) as usize,
        (i32::from(window.Bottom) - i32::from(window.Top) + 1).max(1) as usize,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
    input: HANDLE,
    output: HANDLE,
    input_mode: u32,
    output_mode: u32,
    surrogate: Option<u16>,
    handler: bool,
}

impl Terminal {
    pub fn enter() -> io::Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(io::Error::other(
                "se requiere una terminal interactiva de Windows",
            ));
        }
        let input = console_handle(STD_INPUT_HANDLE)?;
        let output = console_handle(STD_OUTPUT_HANDLE)?;
        let mut terminal = Self {
            input,
            output,
            input_mode: console_mode(input)?,
            output_mode: console_mode(output)?,
            surrogate: None,
            handler: false,
        };
        let input_mode = (terminal.input_mode | ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT)
            & !(ENABLE_ECHO_INPUT
                | ENABLE_LINE_INPUT
                | ENABLE_PROCESSED_INPUT
                | ENABLE_QUICK_EDIT_MODE
                | ENABLE_VIRTUAL_TERMINAL_INPUT
                | ENABLE_MOUSE_INPUT);
        set_mode(input, input_mode)?;
        set_mode(
            output,
            terminal.output_mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        )?;
        if unsafe { SetConsoleCtrlHandler(Some(stop), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        terminal.handler = true;
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
        let wait = timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32;
        match unsafe { WaitForSingleObject(self.input, wait) } {
            WAIT_TIMEOUT => return Ok(Vec::new()),
            WAIT_OBJECT_0 => (),
            _ => return Err(io::Error::last_os_error()),
        }
        let mut records = [INPUT_RECORD::default(); 64];
        let mut count = 0;
        if unsafe {
            ReadConsoleInputW(
                self.input,
                records.as_mut_ptr(),
                records.len() as u32,
                &mut count,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut keys = Vec::new();
        for record in &records[..count as usize] {
            if u32::from(record.EventType) != KEY_EVENT {
                continue;
            }
            let event = unsafe { record.Event.KeyEvent };
            if event.bKeyDown == 0 {
                continue;
            }
            if let Some(key) = self.key(event) {
                keys.extend(std::iter::repeat_n(
                    key,
                    usize::from(event.wRepeatCount.max(1)),
                ));
            }
        }
        Ok(keys)
    }

    fn key(&mut self, event: KEY_EVENT_RECORD) -> Option<Key> {
        let unit = unsafe { event.uChar.UnicodeChar };
        if unit == 3
            || (event.wVirtualKeyCode == 0x43
                && event.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0)
        {
            return Some(Key::Interrupt);
        }
        if (0xd800..=0xdbff).contains(&unit) {
            self.surrogate = Some(unit);
            return None;
        }
        let previous = self.surrogate.take();
        let key = match event.wVirtualKeyCode {
            VK_UP => Key::Up,
            VK_DOWN => Key::Down,
            VK_PRIOR => Key::PageUp,
            VK_NEXT => Key::PageDown,
            VK_HOME => Key::Home,
            VK_END => Key::End,
            VK_RETURN => Key::Enter,
            VK_ESCAPE => Key::Esc,
            VK_BACK => Key::Backspace,
            _ => {
                let cp = if let Some(high) = previous.filter(|_| (0xdc00..=0xdfff).contains(&unit))
                {
                    0x10000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(unit) - 0xdc00)
                } else {
                    u32::from(unit)
                };
                Key::Char(char::from_u32(cp).filter(|ch| !ch.is_control())?)
            }
        };
        Some(key)
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if self.handler {
            let _ = self.draw("\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1049l");
        }
        let _ = set_mode(self.input, self.input_mode);
        let _ = set_mode(self.output, self.output_mode);
        if self.handler {
            unsafe { SetConsoleCtrlHandler(Some(stop), 0) };
        }
    }
}

fn console_handle(which: STD_HANDLE) -> io::Result<HANDLE> {
    let handle = unsafe { GetStdHandle(which) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(handle)
    }
}

fn console_mode(handle: HANDLE) -> io::Result<u32> {
    let mut mode = 0;
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(mode)
    }
}

fn set_mode(handle: HANDLE, mode: u32) -> io::Result<()> {
    if unsafe { SetConsoleMode(handle, mode) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
