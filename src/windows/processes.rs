use super::Handle;
use crate::process::{Process, ProcessKey};
use anyhow::{Context, Result};
use std::io;
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_FILES, FILETIME},
    System::{Diagnostics::ToolHelp::*, Threading::*},
};

pub fn snapshot() -> Result<Vec<Process>> {
    let snapshot = Handle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })
        .context("enumerar los procesos de Windows")?;
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    let mut processes = Vec::new();
    let mut path_buffer = vec![0u16; 32768];
    while more != 0 {
        let pid = entry.th32ProcessID;
        let name_end = entry
            .szExeFile
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(entry.szExeFile.len());
        let (key, executable) = image(pid, &mut path_buffer);
        processes.push(Process {
            key,
            name: String::from_utf16_lossy(&entry.szExeFile[..name_end]),
            sockets: None,
            executable,
        });
        more = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
        return Err(error).context("leer la lista de procesos de Windows");
    }
    Ok(processes)
}

pub fn image(pid: u32, buffer: &mut [u16]) -> (ProcessKey, Option<Vec<u16>>) {
    let fallback = (ProcessKey::new(pid, 0), None);
    let Ok(process) =
        Handle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })
    else {
        return fallback;
    };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) } == 0
        || exit.dwHighDateTime != 0
        || exit.dwLowDateTime != 0
    {
        return fallback;
    }
    let creation = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    let key = ProcessKey::new(pid, creation);
    let mut len = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(process.0, 0, buffer.as_mut_ptr(), &mut len) };
    let path = (ok != 0).then(|| {
        let mut path = buffer[..len as usize].to_vec();
        path.push(0);
        path
    });
    (key, path)
}
