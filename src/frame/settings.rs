use std::fmt;

use crate::frame::{util, Error, Frame, FrameSize, Head, Kind, StreamId};
use crate::tracing;
use bytes::{BufMut, BytesMut};
use smallvec::SmallVec;

/// The maximum number of settings that can be sent in a SETTINGS frame.
const DEFAULT_SETTING_STACK_SIZE: usize = 8;

define_enum_with_values! {
    /// An enum that lists all valid settings that can be sent in a SETTINGS
    /// frame.
    ///
    /// Each setting has a value that is a 32 bit unsigned integer (6.5.1.).
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc9113#name-defined-settings.
    pub enum SettingId {
        /// This setting allows the sender to inform the remote endpoint
        /// of the maximum size of the compression table used to decode field blocks,
        /// in units of octets. The encoder can select any size equal to or less than
        /// this value by using signaling specific to the compression format inside
        /// a field block (see [COMPRESSION]). The initial value is 4,096 octets.
        ///
        /// [COMPRESSION]: https://datatracker.ietf.org/doc/html/rfc7541
        HeaderTableSize => 0x0001,

        /// Enables or disables server push.
        EnablePush => 0x0002,

        /// Specifies the maximum number of concurrent streams.
        MaxConcurrentStreams => 0x0003,

        /// Sets the initial stream-level flow control window size.
        InitialWindowSize => 0x0004,

        /// Indicates the largest acceptable frame payload size.
        MaxFrameSize => 0x0005,

        /// Advises the peer of the max field section size.
        MaxHeaderListSize => 0x0006,

        /// Enables support for the Extended CONNECT protocol.
        EnableConnectProtocol => 0x0008,
    }
}

impl SettingId {
    /// The maximum allowed SettingId value for bitmask operations.
    /// This should not exceed the number of bits in the mask type (u16: 16, u32: 32, etc.)
    const MAX_SETTING_ID: u16 = 15;

    /// The default setting IDs that are used when no specific order is provided.
    const DEFAULT_IDS: [SettingId; DEFAULT_SETTING_STACK_SIZE] = [
        SettingId::HeaderTableSize,
        SettingId::EnablePush,
        SettingId::InitialWindowSize,
        SettingId::MaxConcurrentStreams,
        SettingId::MaxFrameSize,
        SettingId::MaxHeaderListSize,
        SettingId::EnableConnectProtocol,
        SettingId::Unknown(0x09),
    ];

    fn mask_id(self) -> u16 {
        let value = u16::from(self);
        if value == 0 || value > Self::MAX_SETTING_ID {
            return 0;
        }

        1 << (value - 1)
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct SettingsOrder {
    ids: SmallVec<[SettingId; DEFAULT_SETTING_STACK_SIZE]>,
    mask: u16,
}

impl SettingsOrder {
    /// Push a setting ID into the order.
    pub fn push(&mut self, id: SettingId) {
        let mask_id = id.mask_id();

        // If the ID is 0 or greater than the max setting ID, ignore it.
        if mask_id == 0 {
            return;
        }

        if self.mask & mask_id == 0 {
            self.mask |= mask_id;
            self.ids.push(id);
        } else {
            tracing::trace!("duplicate setting ID ignored: {id:?}");
        }
    }

    /// Push a setting ID into the order, and extend the order with default IDs.
    pub fn extend(&mut self, iter: impl IntoIterator<Item = SettingId>) {
        for id in iter {
            self.push(id);
        }
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct Settings {
    flags: SettingsFlags,
    // Fields
    header_table_size: Option<u32>,
    enable_push: Option<u32>,
    max_concurrent_streams: Option<u32>,
    initial_window_size: Option<u32>,
    max_frame_size: Option<u32>,
    max_header_list_size: Option<u32>,
    enable_connect_protocol: Option<u32>,
    unknown_settings: Option<SmallVec<[Setting; DEFAULT_SETTING_STACK_SIZE]>>,
    // Settings order
    settings_order: Option<SettingsOrder>,
}

/// An enum that lists all valid settings that can be sent in a SETTINGS
/// frame.
///
/// Each setting has a value that is a 32 bit unsigned integer (6.5.1.).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Setting {
    id: SettingId,
    value: u32,
}

#[derive(Copy, Clone, Eq, PartialEq, Default)]
pub struct SettingsFlags(u8);

const ACK: u8 = 0x1;
const ALL: u8 = ACK;

/// The default value of SETTINGS_HEADER_TABLE_SIZE
pub const DEFAULT_SETTINGS_HEADER_TABLE_SIZE: usize = 4_096;

/// The default value of SETTINGS_INITIAL_WINDOW_SIZE
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;

/// The default value of MAX_FRAME_SIZE
pub const DEFAULT_MAX_FRAME_SIZE: FrameSize = 16_384;

/// INITIAL_WINDOW_SIZE upper bound
pub const MAX_INITIAL_WINDOW_SIZE: usize = (1 << 31) - 1;

/// MAX_FRAME_SIZE upper bound
pub const MAX_MAX_FRAME_SIZE: FrameSize = (1 << 24) - 1;

// ===== impl Settings =====

impl Settings {
    pub fn ack() -> Settings {
        Settings {
            flags: SettingsFlags::ack(),
            ..Settings::default()
        }
    }

    pub fn is_ack(&self) -> bool {
        self.flags.is_ack()
    }

    pub fn initial_window_size(&self) -> Option<u32> {
        self.initial_window_size
    }

    pub fn set_initial_window_size(&mut self, size: Option<u32>) {
        self.initial_window_size = size;
    }

    pub fn max_concurrent_streams(&self) -> Option<u32> {
        self.max_concurrent_streams
    }

    pub fn set_max_concurrent_streams(&mut self, max: Option<u32>) {
        self.max_concurrent_streams = max;
    }

    pub fn max_frame_size(&self) -> Option<u32> {
        self.max_frame_size
    }

    pub fn set_max_frame_size(&mut self, size: Option<u32>) {
        if let Some(val) = size {
            assert!(DEFAULT_MAX_FRAME_SIZE <= val && val <= MAX_MAX_FRAME_SIZE);
        }
        self.max_frame_size = size;
    }

    pub fn max_header_list_size(&self) -> Option<u32> {
        self.max_header_list_size
    }

    pub fn set_max_header_list_size(&mut self, size: Option<u32>) {
        self.max_header_list_size = size;
    }

    pub fn is_push_enabled(&self) -> Option<bool> {
        self.enable_push.map(|val| val != 0)
    }

    pub fn set_enable_push(&mut self, enable: bool) {
        self.enable_push = Some(enable as u32);
    }

    pub fn is_extended_connect_protocol_enabled(&self) -> Option<bool> {
        self.enable_connect_protocol.map(|val| val != 0)
    }

    pub fn set_enable_connect_protocol(&mut self, val: Option<u32>) {
        self.enable_connect_protocol = val;
    }

    pub fn header_table_size(&self) -> Option<u32> {
        self.header_table_size
    }

    pub fn set_header_table_size(&mut self, size: Option<u32>) {
        self.header_table_size = size;
    }

    pub fn set_unknown_settings(&mut self, settings: impl IntoIterator<Item = Setting>) {
        let unknown_settings = self.unknown_settings.get_or_insert_with(SmallVec::new);
        unknown_settings.extend(settings);
    }

    pub fn set_settings_order(&mut self, settings_order: Option<SettingsOrder>) {
        self.settings_order = settings_order;
    }

    pub fn load(head: Head, payload: &[u8]) -> Result<Settings, Error> {
        debug_assert_eq!(head.kind(), crate::frame::Kind::Settings);

        if !head.stream_id().is_zero() {
            return Err(Error::InvalidStreamId);
        }

        // Load the flag
        let flag = SettingsFlags::load(head.flag());

        if flag.is_ack() {
            // Ensure that the payload is empty
            if !payload.is_empty() {
                return Err(Error::InvalidPayloadLength);
            }

            // Return the ACK frame
            return Ok(Settings::ack());
        }

        // Ensure the payload length is correct, each setting is 6 bytes long.
        if payload.len() % 6 != 0 {
            tracing::debug!("invalid settings payload length; len={:?}", payload.len());
            return Err(Error::InvalidPayloadAckSettings);
        }

        let mut settings = Settings::default();
        debug_assert!(!settings.flags.is_ack());

        for raw in payload.chunks(6) {
            match Setting::load(raw) {
                Some(setting) => match setting.id {
                    SettingId::HeaderTableSize => {
                        settings.header_table_size = Some(setting.value);
                    }
                    SettingId::EnablePush => match setting.value {
                        0 | 1 => {
                            settings.enable_push = Some(setting.value);
                        }
                        _ => {
                            return Err(Error::InvalidSettingValue);
                        }
                    },
                    SettingId::MaxConcurrentStreams => {
                        settings.max_concurrent_streams = Some(setting.value);
                    }
                    SettingId::InitialWindowSize => {
                        if setting.value as usize > MAX_INITIAL_WINDOW_SIZE {
                            return Err(Error::InvalidSettingValue);
                        } else {
                            settings.initial_window_size = Some(setting.value);
                        }
                    }
                    SettingId::MaxFrameSize => {
                        if DEFAULT_MAX_FRAME_SIZE <= setting.value
                            && setting.value <= MAX_MAX_FRAME_SIZE
                        {
                            settings.max_frame_size = Some(setting.value);
                        } else {
                            return Err(Error::InvalidSettingValue);
                        }
                    }
                    SettingId::MaxHeaderListSize => {
                        settings.max_header_list_size = Some(setting.value);
                    }
                    SettingId::EnableConnectProtocol => match setting.value {
                        0 | 1 => {
                            settings.enable_connect_protocol = Some(setting.value);
                        }
                        _ => {
                            return Err(Error::InvalidSettingValue);
                        }
                    },
                    SettingId::Unknown(_) => {
                        settings
                            .unknown_settings
                            .get_or_insert_with(SmallVec::new)
                            .push(setting);
                    }
                },
                None => {}
            }
        }

        Ok(settings)
    }

    fn payload_len(&self) -> usize {
        let mut len = 0;
        self.for_each(|_| len += 6);
        len
    }

    pub fn encode(&self, dst: &mut BytesMut) {
        // Create & encode an appropriate frame head
        let head = Head::new(Kind::Settings, self.flags.into(), StreamId::zero());
        let payload_len = self.payload_len();

        tracing::trace!("encoding SETTINGS; len={}", payload_len);

        head.encode(payload_len, dst);

        // Encode the settings
        self.for_each(|setting| {
            tracing::trace!("encoding setting; val={:?}", setting);
            setting.encode(dst)
        });
    }

    fn for_each<F: FnMut(Setting)>(&self, mut f: F) {
        let ids = self
            .settings_order
            .as_ref()
            .map(|order| order.ids.as_ref())
            .unwrap_or(&SettingId::DEFAULT_IDS);

        for id in ids {
            match id {
                SettingId::HeaderTableSize => {
                    if let Some(v) = self.header_table_size {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::EnablePush => {
                    if let Some(v) = self.enable_push {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::MaxConcurrentStreams => {
                    if let Some(v) = self.max_concurrent_streams {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::InitialWindowSize => {
                    if let Some(v) = self.initial_window_size {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::MaxFrameSize => {
                    if let Some(v) = self.max_frame_size {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::MaxHeaderListSize => {
                    if let Some(v) = self.max_header_list_size {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::EnableConnectProtocol => {
                    if let Some(v) = self.enable_connect_protocol {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::Unknown(id) => {
                    if let Some(ref unknown_settings) = self.unknown_settings {
                        if let Some(setting) = unknown_settings
                            .iter()
                            .find(|setting| setting.id == SettingId::Unknown(*id))
                        {
                            f(setting.clone());
                        }
                    }
                }
            }
        }
    }
}

impl<T> From<Settings> for Frame<T> {
    fn from(src: Settings) -> Frame<T> {
        Frame::Settings(src)
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("Settings");
        builder.field("flags", &self.flags);

        self.for_each(|setting| match setting.id {
            SettingId::EnablePush => {
                builder.field("enable_push", &setting.value);
            }
            SettingId::HeaderTableSize => {
                builder.field("header_table_size", &setting.value);
            }
            SettingId::InitialWindowSize => {
                builder.field("initial_window_size", &setting.value);
            }
            SettingId::MaxConcurrentStreams => {
                builder.field("max_concurrent_streams", &setting.value);
            }
            SettingId::MaxFrameSize => {
                builder.field("max_frame_size", &setting.value);
            }
            SettingId::MaxHeaderListSize => {
                builder.field("max_header_list_size", &setting.value);
            }
            SettingId::EnableConnectProtocol => {
                builder.field("enable_connect_protocol", &setting.value);
            }
            SettingId::Unknown(id) => {
                builder.field("unknown", &format!("id={id:?}, val={}", setting.value));
            }
        });

        builder.finish()
    }
}

// ===== impl Setting =====

impl Setting {
    /// Creates a new `Setting` with the correct variant corresponding to the
    /// given setting id, based on the settings IDs defined in section
    /// 6.5.2.
    pub fn from_id(id: impl Into<SettingId>, value: u32) -> Option<Setting> {
        let id = id.into();
        if let SettingId::Unknown(id) = id {
            if id == 0 || id > SettingId::MAX_SETTING_ID {
                tracing::debug!("limiting unknown setting id to 0x0..0xF");
                return None;
            }
        }

        Some(Setting { id, value })
    }

    /// Creates a new `Setting` by parsing the given buffer of 6 bytes, which
    /// contains the raw byte representation of the setting, according to the
    /// "SETTINGS format" defined in section 6.5.1.
    ///
    /// The `raw` parameter should have length at least 6 bytes, since the
    /// length of the raw setting is exactly 6 bytes.
    ///
    /// # Panics
    ///
    /// If given a buffer shorter than 6 bytes, the function will panic.
    fn load(raw: &[u8]) -> Option<Setting> {
        let id: u16 = (u16::from(raw[0]) << 8) | u16::from(raw[1]);
        let val: u32 = unpack_octets_4!(raw, 2, u32);

        Setting::from_id(id, val)
    }

    fn encode(&self, dst: &mut BytesMut) {
        let kind = u16::from(self.id);
        let val = self.value;

        dst.put_u16(kind);
        dst.put_u32(val);
    }
}

// ===== impl SettingsFlags =====

impl SettingsFlags {
    pub fn empty() -> SettingsFlags {
        SettingsFlags(0)
    }

    pub fn load(bits: u8) -> SettingsFlags {
        SettingsFlags(bits & ALL)
    }

    pub fn ack() -> SettingsFlags {
        SettingsFlags(ACK)
    }

    pub fn is_ack(&self) -> bool {
        self.0 & ACK == ACK
    }
}

impl From<SettingsFlags> for u8 {
    fn from(src: SettingsFlags) -> u8 {
        src.0
    }
}

impl fmt::Debug for SettingsFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        util::debug_flags(f, self.0)
            .flag_if(self.is_ack(), "ACK")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extend_with_default(order: &mut SettingsOrder) {
        const MASK: u16 = 1 << SettingId::MAX_SETTING_ID;
        if order.mask & MASK == MASK {
            return;
        }
        order.extend(SettingId::DEFAULT_IDS);
    }

    #[test]
    fn test_extend_with_default_only_adds_once() {
        let mut order = SettingsOrder::default();
        assert!(order.ids.is_empty());
        assert_eq!(order.mask, 0);

        extend_with_default(&mut order);
        assert_eq!(order.ids.len(), DEFAULT_SETTING_STACK_SIZE);

        let orig_order = order.clone();
        let n = order.ids.len();
        extend_with_default(&mut order);
        assert_eq!(order.ids.len(), n);
        assert_eq!(order, orig_order);
    }

    #[test]
    fn test_extend_with_default_and_unknown_ids() {
        let mut order = SettingsOrder::default();
        extend_with_default(&mut order);
        order.extend([SettingId::Unknown(10)]);
        assert_eq!(order.ids.len(), DEFAULT_SETTING_STACK_SIZE + 1);

        extend_with_default(&mut order);
        assert_eq!(order.ids.len(), DEFAULT_SETTING_STACK_SIZE + 1);

        order.extend([SettingId::Unknown(10)]);
        assert_eq!(order.ids.len(), DEFAULT_SETTING_STACK_SIZE + 1);

        order.extend([SettingId::Unknown(11)]);
        assert_eq!(order.ids.len(), DEFAULT_SETTING_STACK_SIZE + 2);

        order.extend([SettingId::Unknown(15)]);
        assert_eq!(order.ids.len(), DEFAULT_SETTING_STACK_SIZE + 3);

        // ID > MAX_SETTING_ID
        order.extend([SettingId::Unknown(16)]);
        assert_eq!(order.ids.len(), DEFAULT_SETTING_STACK_SIZE + 3);
    }
}
