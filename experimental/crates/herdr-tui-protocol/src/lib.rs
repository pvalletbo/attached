//! Minimal Herdr v0.7.5 thin-client wire protocol.
//!
//! Derived from Herdr's `src/protocol/wire.rs` at tag `v0.7.5`, then modified
//! for Attached's minimal standalone codec on 2026-08-01.

use std::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const PROTOCOL_VERSION: u32 = 17;
pub const MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_GRAPHICS_FRAME_SIZE: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenderEncoding {
    SemanticFrame,
    TerminalAnsi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientKeybindings {
    Server,
    Local { keys_toml: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientLaunchMode {
    App,
    TerminalAttach,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientKeyKind {
    Press,
    Repeat,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientKeyCode {
    Backspace,
    Enter,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Tab,
    BackTab,
    Delete,
    Insert,
    Esc,
    Char(char),
    F(u8),
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMouseButton {
    Left,
    Right,
    Middle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMouseKind {
    Down(ClientMouseButton),
    Up(ClientMouseButton),
    Drag(ClientMouseButton),
    Moved,
    ScrollUp,
    ScrollDown,
    ScrollLeft,
    ScrollRight,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientInputEvent {
    Key {
        code: ClientKeyCode,
        modifiers: u8,
        kind: ClientKeyKind,
    },
    Mouse {
        kind: ClientMouseKind,
        column: u16,
        row: u16,
        modifiers: u8,
    },
    Paste {
        text: String,
    },
    FocusGained,
    FocusLost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMessage {
    Hello {
        version: u32,
        cols: u16,
        rows: u16,
        cell_width_px: u32,
        cell_height_px: u32,
        requested_encoding: RenderEncoding,
        keybindings: ClientKeybindings,
        launch_mode: ClientLaunchMode,
    },
    Input {
        data: Vec<u8>,
    },
    ClipboardImage {
        extension: String,
        data: Vec<u8>,
    },
    Resize {
        cols: u16,
        rows: u16,
        cell_width_px: u32,
        cell_height_px: u32,
    },
    Detach,
    AttachTerminal {
        terminal_id: String,
        takeover: bool,
    },
    AttachScroll {
        source: AttachScrollSource,
        direction: AttachScrollDirection,
        lines: u16,
        column: Option<u16>,
        row: Option<u16>,
        modifiers: u8,
    },
    InputEvents {
        events: Vec<ClientInputEvent>,
    },
    ObserveTerminal {
        target: String,
    },
    ControlTerminal {
        target: String,
        takeover: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachScrollDirection {
    Up,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachScrollSource {
    Wheel,
    PageKey { input: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellData {
    pub symbol: String,
    pub fg: u32,
    pub bg: u32,
    pub modifier: u16,
    pub skip: bool,
    pub hyperlink: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorState {
    pub x: u16,
    pub y: u16,
    pub visible: bool,
    #[serde(default)]
    pub shape: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameData {
    pub cells: Vec<CellData>,
    pub width: u16,
    pub height: u16,
    pub cursor: Option<CursorState>,
    pub hyperlinks: Vec<String>,
    pub graphics: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalFrame {
    pub seq: u64,
    pub width: u16,
    pub height: u16,
    pub full: bool,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotifyKind {
    Sound,
    Toast,
    SystemToast,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    Welcome {
        version: u32,
        encoding: RenderEncoding,
        error: Option<String>,
    },
    Frame(FrameData),
    Terminal(TerminalFrame),
    Graphics {
        bytes: Vec<u8>,
    },
    ServerShutdown {
        reason: Option<String>,
    },
    Notify {
        kind: NotifyKind,
        message: String,
        body: Option<String>,
    },
    Clipboard {
        data: String,
    },
    WindowTitle {
        title: Option<String>,
    },
    ReloadSoundConfig,
    MouseCapture {
        enabled: bool,
    },
    PrefixInputSource {
        active: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Oversized { claimed: usize, max: usize },
    Bincode(String),
    TrailingBytes { consumed: usize, payload: usize },
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversized { claimed, max } => {
                write!(formatter, "frame size {claimed} exceeds maximum {max}")
            }
            Self::Bincode(error) => write!(formatter, "bincode error: {error}"),
            Self::TrailingBytes { consumed, payload } => write!(
                formatter,
                "decoded {consumed} bytes but payload length was {payload}"
            ),
        }
    }
}

impl std::error::Error for CodecError {}

pub fn encode_message<M: Serialize>(message: &M) -> Result<Vec<u8>, CodecError> {
    let payload = bincode::serde::encode_to_vec(message, bincode::config::standard())
        .map_err(|error| CodecError::Bincode(error.to_string()))?;
    let length = u32::try_from(payload.len()).map_err(|_| CodecError::Oversized {
        claimed: payload.len(),
        max: u32::MAX as usize,
    })?;

    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&length.to_le_bytes());
    framed.extend_from_slice(&payload);
    Ok(framed)
}

#[cfg(target_arch = "wasm32")]
mod wasm;

pub fn decode_payload<M: DeserializeOwned>(
    payload: &[u8],
    max_frame_size: usize,
) -> Result<M, CodecError> {
    if payload.len() > max_frame_size {
        return Err(CodecError::Oversized {
            claimed: payload.len(),
            max: max_frame_size,
        });
    }

    let (message, consumed) =
        bincode::serde::decode_from_slice(payload, bincode::config::standard())
            .map_err(|error| CodecError::Bincode(error.to_string()))?;
    if consumed != payload.len() {
        return Err(CodecError::TrailingBytes {
            consumed,
            payload: payload.len(),
        });
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_uses_the_expected_wire_tag_and_round_trips() {
        let hello = ClientMessage::Hello {
            version: PROTOCOL_VERSION,
            cols: 120,
            rows: 36,
            cell_width_px: 0,
            cell_height_px: 0,
            requested_encoding: RenderEncoding::TerminalAnsi,
            keybindings: ClientKeybindings::Server,
            launch_mode: ClientLaunchMode::App,
        };

        let framed = encode_message(&hello).unwrap();
        assert_eq!(framed[4], 0);
        let decoded = decode_payload::<ClientMessage>(&framed[4..], MAX_FRAME_SIZE).unwrap();
        assert_eq!(decoded, hello);
    }

    #[test]
    fn input_and_resize_preserve_protocol_17_variant_order() {
        let input = encode_message(&ClientMessage::Input { data: Vec::new() }).unwrap();
        let resize = encode_message(&ClientMessage::Resize {
            cols: 80,
            rows: 24,
            cell_width_px: 0,
            cell_height_px: 0,
        })
        .unwrap();

        assert_eq!(input[4], 1);
        assert_eq!(resize[4], 3);
    }
}
