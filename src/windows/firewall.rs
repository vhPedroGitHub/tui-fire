use super::status;
use anyhow::{Context, Result, ensure};
use std::{
    ffi::c_void,
    ptr::{self, NonNull},
};
use windows_sys::{
    Win32::{
        Foundation::HANDLE,
        Globalization::{CSTR_EQUAL, CompareStringOrdinal},
        NetworkManagement::WindowsFilteringPlatform::*,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
    core::{GUID, w},
};

const SUBLAYER: GUID = GUID::from_u128(0x307dc00b_249f_41ee_8b51_c7a1e8fd443e);
const LAYERS: [GUID; 4] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];

struct Rule {
    path: Vec<u16>,
    filters: [u64; LAYERS.len()],
}

pub struct Firewall {
    engine: HANDLE,
    rules: Vec<Rule>,
}

impl Firewall {
    pub fn new() -> Result<Self> {
        let session = FWPM_SESSION0 {
            displayData: display_name(),
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            txnWaitTimeoutInMSec: 2000,
            ..Default::default()
        };
        let mut engine = ptr::null_mut();
        status(unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut engine,
            )
        })
        .context("abrir el firewall de Windows como administrador")?;
        let firewall = Self {
            engine,
            rules: Vec::new(),
        };
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER,
            displayData: display_name(),
            weight: u16::MAX,
            ..Default::default()
        };
        status(unsafe { FwpmSubLayerAdd0(firewall.engine, &sublayer, ptr::null_mut()) })
            .context("crear la subcapa temporal de TUI Fire")?;
        Ok(firewall)
    }

    pub fn blocked(&self, path: &[u16]) -> bool {
        self.rule_index(path).is_some()
    }

    fn rule_index(&self, path: &[u16]) -> Option<usize> {
        self.rules.iter().position(|rule| unsafe {
            CompareStringOrdinal(
                path.as_ptr(),
                path.len() as i32,
                rule.path.as_ptr(),
                rule.path.len() as i32,
                1,
            ) == CSTR_EQUAL
        })
    }

    pub fn toggle(&mut self, path: &[u16]) -> Result<bool> {
        if let Some(index) = self.rule_index(path) {
            self.transaction(|| {
                for id in self.rules[index].filters {
                    status(unsafe { FwpmFilterDeleteById0(self.engine, id) })?;
                }
                Ok(())
            })
            .context("retirar los filtros del ejecutable")?;
            self.rules.swap_remove(index);
            return Ok(false);
        }

        let app = AppId::new(path)?;
        let filters = self
            .transaction(|| {
                let mut conditions = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            byteBlob: app.0.as_ptr(),
                        },
                    },
                };
                let mut ids = [0; LAYERS.len()];
                for (id, layer) in ids.iter_mut().zip(LAYERS) {
                    let filter = FWPM_FILTER0 {
                        displayData: display_name(),
                        layerKey: layer,
                        subLayerKey: SUBLAYER,
                        numFilterConditions: 1,
                        filterCondition: &mut conditions,
                        action: FWPM_ACTION0 {
                            r#type: FWP_ACTION_BLOCK,
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    status(unsafe { FwpmFilterAdd0(self.engine, &filter, ptr::null_mut(), id) })?;
                }
                Ok(ids)
            })
            .context("activar los filtros de entrada y salida del ejecutable")?;
        self.rules.push(Rule {
            path: path.to_vec(),
            filters,
        });
        Ok(true)
    }

    fn transaction<T>(&self, change: impl FnOnce() -> Result<T>) -> Result<T> {
        status(unsafe { FwpmTransactionBegin0(self.engine, 0) })?;
        let result = change().and_then(|value| {
            status(unsafe { FwpmTransactionCommit0(self.engine) })?;
            Ok(value)
        });
        if result.is_err() {
            unsafe { FwpmTransactionAbort0(self.engine) };
        }
        result
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

struct AppId(NonNull<FWP_BYTE_BLOB>);

impl AppId {
    fn new(path: &[u16]) -> Result<Self> {
        ensure!(path.last() == Some(&0), "ruta de ejecutable sin terminar");
        let mut blob = ptr::null_mut();
        status(unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) })
            .context("obtener el identificador del ejecutable para el firewall")?;
        Ok(Self(
            NonNull::new(blob).context("el firewall devolvió un identificador vacío")?,
        ))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        let mut pointer: *mut c_void = self.0.as_ptr().cast();
        unsafe { FwpmFreeMemory0(&mut pointer) };
    }
}

fn display_name() -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: w!("TUI Fire").cast_mut(),
        description: ptr::null_mut(),
    }
}
