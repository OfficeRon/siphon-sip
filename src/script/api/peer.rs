//! `siphon.peer` — one WebRTC agent per call leg, in this process.

use std::sync::Arc;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::{json, Value};

use crate::peer::{Handle, IceServerIn};

#[pyclass(name = "PeerNamespace")]
pub struct PyPeer {
    handle: Arc<Handle>,
}

impl PyPeer {
    pub fn new(handle: Arc<Handle>) -> Self {
        Self { handle }
    }
}

fn runtime(err: String) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(err)
}

fn ice_from_json(raw: &str) -> Vec<IceServerIn> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    let Some(list) = value.as_array() else {
        return Vec::new();
    };
    list.iter().filter_map(|item| {
        let urls = item.get("urls").and_then(|urls| urls.as_str()).unwrap_or("");
        if urls.is_empty() {
            return None;
        }
        Some(IceServerIn {
            urls: urls.to_string(),
            username: item.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            credential: item.get("credential").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        })
    }).collect()
}

#[pymethods]
impl PyPeer {
    fn available(&self) -> bool {
        true
    }

    fn create<'py>(
        &self,
        py: Python<'py>,
        session_id: String,
        leg: String,
        want_audio: bool,
        ice_json: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        let ice = ice_from_json(&ice_json);
        let leg_out = leg.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let epoch = handle.create(&session_id, &leg, want_audio, ice).await.map_err(runtime)?;
            Ok(json!({"ok": true, "leg": leg_out, "epoch": epoch}).to_string())
        })
    }

    fn set_remote<'py>(
        &self,
        py: Python<'py>,
        session_id: String,
        leg: String,
        kind: String,
        sdp: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.set_remote(&session_id, &leg, &kind, &sdp).await.map_err(runtime)?;
            Ok(json!({"ok": true}).to_string())
        })
    }

    fn add_ice<'py>(
        &self,
        py: Python<'py>,
        session_id: String,
        leg: String,
        candidates_json: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        let lines: Vec<String> = serde_json::from_str(&candidates_json).unwrap_or_default();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let added = handle.add_ice(&session_id, &leg, lines).await.map_err(runtime)?;
            Ok(json!({"ok": true, "added": added}).to_string())
        })
    }

    fn create_offer<'py>(&self, py: Python<'py>, session_id: String, leg: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let out = handle.create_offer(&session_id, &leg).await.map_err(runtime)?;
            Ok(json!({"sdp": out.sdp, "candidates": out.candidates}).to_string())
        })
    }

    fn create_answer<'py>(&self, py: Python<'py>, session_id: String, leg: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let out = handle.create_answer(&session_id, &leg).await.map_err(runtime)?;
            Ok(json!({"sdp": out.sdp, "candidates": out.candidates}).to_string())
        })
    }

    fn local_ice<'py>(&self, py: Python<'py>, session_id: String, leg: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let candidates = handle.local_ice(&session_id, &leg).await;
            Ok(json!({"candidates": candidates}).to_string())
        })
    }

    fn wait_connected<'py>(
        &self,
        py: Python<'py>,
        session_id: String,
        leg: String,
        timeout_ms: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let out = handle.wait_connected(&session_id, &leg, Duration::from_millis(timeout_ms)).await;
            Ok(json!({"ok": out.ok, "state": out.state, "ice": out.ice, "dtls": out.dtls}).to_string())
        })
    }

    fn send<'py>(&self, py: Python<'py>, session_id: String, leg: String, text: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.send_text(&session_id, &leg, &text).await.map_err(runtime)?;
            Ok(json!({"ok": true}).to_string())
        })
    }

    fn rotate<'py>(&self, py: Python<'py>, session_id: String, leg: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.rotate(&session_id, &leg).await.map_err(runtime)?;
            Ok(json!({"ok": true}).to_string())
        })
    }

    fn dtmf<'py>(&self, py: Python<'py>, session_id: String, leg: String, digit: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        let digit = digit.chars().next().unwrap_or('0');
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.dtmf(&session_id, &leg, digit).await.map_err(runtime)?;
            Ok(json!({"ok": true}).to_string())
        })
    }

    fn bridge<'py>(&self, py: Python<'py>, session_id: String, a: String, b: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.bridge(&session_id, &a, &b).await.map_err(runtime)?;
            Ok(json!({"ok": true}).to_string())
        })
    }

    fn unbridge<'py>(&self, py: Python<'py>, session_id: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.unbridge(&session_id).await;
            Ok(json!({"ok": true}).to_string())
        })
    }

    fn close<'py>(&self, py: Python<'py>, session_id: String, leg: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.close(&session_id, &leg).await;
            Ok(json!({"ok": true}).to_string())
        })
    }

    fn abandon<'py>(&self, py: Python<'py>, session_id: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = Arc::clone(&self.handle);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.abandon(&session_id).await;
            Ok(json!({"ok": true}).to_string())
        })
    }

    fn poll_event(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<Option<Py<PyDict>>> {
        let msg = py.detach(|| self.handle.poll_event(Duration::from_millis(timeout_ms)));
        let Some(msg) = msg else { return Ok(None) };
        let dict = PyDict::new(py);
        dict.set_item("event", msg.event)?;
        dict.set_item("sessionId", msg.session_id)?;
        dict.set_item("leg", msg.leg)?;
        dict.set_item("data", msg.data)?;
        dict.set_item("state", msg.state)?;
        dict.set_item("dtls", msg.dtls)?;
        dict.set_item("digit", msg.digit)?;
        Ok(Some(dict.unbind()))
    }
}
