use serde_json::json;
use wasm_bindgen::prelude::*;

use crate::{
    ClientKeybindings, ClientLaunchMode, ClientMessage, MAX_GRAPHICS_FRAME_SIZE, PROTOCOL_VERSION,
    RenderEncoding, ServerMessage, decode_payload, encode_message,
};

const DECODE_OUTPUT: u32 = 1;
const DECODE_CONTROL: u32 = 2;
const DECODE_ERROR: u32 = 3;

#[wasm_bindgen]
pub struct ProtocolDecodeResult {
    kind: u32,
    bytes: Vec<u8>,
}

impl ProtocolDecodeResult {
    fn output(bytes: Vec<u8>) -> Self {
        Self {
            kind: DECODE_OUTPUT,
            bytes,
        }
    }

    fn control(value: serde_json::Value) -> Self {
        match serde_json::to_vec(&value) {
            Ok(bytes) => Self {
                kind: DECODE_CONTROL,
                bytes,
            },
            Err(error) => Self::error(error.to_string()),
        }
    }

    fn error(error: impl Into<String>) -> Self {
        let bytes = serde_json::to_vec(&json!({
            "type": "protocol_error",
            "error": error.into(),
        }))
        .unwrap_or_else(|_| b"{\"type\":\"protocol_error\"}".to_vec());
        Self {
            kind: DECODE_ERROR,
            bytes,
        }
    }
}

#[wasm_bindgen]
impl ProtocolDecodeResult {
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> u32 {
        self.kind
    }

    pub fn take_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

fn encode(message: ClientMessage) -> Result<Vec<u8>, JsError> {
    encode_message(&message).map_err(|error| JsError::new(&error.to_string()))
}

#[wasm_bindgen]
pub fn protocol_encode_hello(columns: u32, rows: u32) -> Result<Vec<u8>, JsError> {
    encode(ClientMessage::Hello {
        version: PROTOCOL_VERSION,
        cols: u16::try_from(columns).unwrap_or(u16::MAX),
        rows: u16::try_from(rows).unwrap_or(u16::MAX),
        cell_width_px: 0,
        cell_height_px: 0,
        requested_encoding: RenderEncoding::TerminalAnsi,
        keybindings: ClientKeybindings::Server,
        launch_mode: ClientLaunchMode::App,
    })
}

#[wasm_bindgen]
pub fn protocol_encode_resize(columns: u32, rows: u32) -> Result<Vec<u8>, JsError> {
    encode(ClientMessage::Resize {
        cols: u16::try_from(columns).unwrap_or(u16::MAX),
        rows: u16::try_from(rows).unwrap_or(u16::MAX),
        cell_width_px: 0,
        cell_height_px: 0,
    })
}

#[wasm_bindgen]
pub fn protocol_encode_input(input: &[u8]) -> Result<Vec<u8>, JsError> {
    encode(ClientMessage::Input {
        data: input.to_vec(),
    })
}

#[wasm_bindgen]
pub fn protocol_encode_detach() -> Result<Vec<u8>, JsError> {
    encode(ClientMessage::Detach)
}

/// Decodes one bincode payload after the four-byte frame prefix has been removed.
#[wasm_bindgen]
pub fn protocol_decode_server(payload: &[u8]) -> ProtocolDecodeResult {
    let message = match decode_payload::<ServerMessage>(payload, MAX_GRAPHICS_FRAME_SIZE) {
        Ok(message) => message,
        Err(error) => return ProtocolDecodeResult::error(error.to_string()),
    };

    match message {
        ServerMessage::Welcome {
            version,
            encoding: RenderEncoding::TerminalAnsi,
            error: None,
        } if version == PROTOCOL_VERSION => ProtocolDecodeResult::control(json!({
            "type": "ready",
            "protocol": version,
        })),
        ServerMessage::Welcome { version, error, .. } => ProtocolDecodeResult::error(format!(
            "Herdr rejected protocol handshake (server protocol {version}): {}",
            error.unwrap_or_else(|| "TerminalAnsi was not negotiated".to_owned())
        )),
        ServerMessage::Terminal(frame) => ProtocolDecodeResult::output(frame.bytes),
        ServerMessage::Graphics { bytes } => ProtocolDecodeResult::output(bytes),
        ServerMessage::ServerShutdown { reason } => ProtocolDecodeResult::control(json!({
            "type": "exit",
            "reason": reason.unwrap_or_else(|| "Herdr server stopped".to_owned()),
        })),
        ServerMessage::Notify {
            kind,
            message,
            body,
        } => ProtocolDecodeResult::control(json!({
            "type": "notification",
            "kind": kind,
            "message": message,
            "body": body,
        })),
        ServerMessage::Clipboard { data } => ProtocolDecodeResult::control(json!({
            "type": "clipboard",
            "data": data,
        })),
        ServerMessage::WindowTitle { title } => ProtocolDecodeResult::control(json!({
            "type": "window_title",
            "title": title,
        })),
        ServerMessage::ReloadSoundConfig => ProtocolDecodeResult::control(json!({
            "type": "reload_sound_config",
        })),
        ServerMessage::MouseCapture { enabled } => ProtocolDecodeResult::control(json!({
            "type": "mouse_capture",
            "enabled": enabled,
        })),
        ServerMessage::PrefixInputSource { active } => ProtocolDecodeResult::control(json!({
            "type": "prefix_input_source",
            "active": active,
        })),
        ServerMessage::Frame(_) => ProtocolDecodeResult::error(
            "Herdr sent a semantic frame after negotiating TerminalAnsi",
        ),
    }
}
