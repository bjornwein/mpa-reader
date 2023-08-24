//! A Rust parser for [MPEG-1 and MPEG-2 Audio](http://mpgedit.org/mpgedit/mpeg_format/mpeghdr.htm)
//! frames used to carry encoded MPEG audio data.
//!
//! [`MpaHeader`](struct.MpaHeader.html) is the primary type provided by this crate.
//!
//! Given a buffer containing some number of MPEG audio frames, the first frame may be inspected by
//! constructing a header instance with,
//!
//! ```rust
//! use mpa_reader::MpaHeader;
//! # let buf: Vec<u8> = vec!(0xff, 0xf5, 0x35, 0);
//! // let buf = ...;
//! match MpaHeader::from_bytes(&buf) {
//!     Ok(header) => println!("length (headers+payload) is {}", header.frame_length().unwrap()),
//!     Err(e) => panic!("failed to read header: {:?}", e),
//! }
//! ```
//!
//! # Unsupported
//!
//!  - "MPEG Version 2.5" (it is not an official standard)
//!  - Resynchronising `MpaParser` after encountering bitstream error (we could search for
//!    sync-word)
//!  - Copyright identifiers (I don't have any example bitstreams to try)
//!  - CRC handling (probably needs to be implemented as part of MPA bitstream parsing)

#![forbid(unsafe_code)]

// TODO: might be better to implement MpaParser as an iterator, rather then doing callbacks into a
// trait implementation -- it looked hard to implement though!

use std::fmt;

#[derive(Debug)]
pub enum MpaHeaderError {
    /// Indicates that the given buffer did not start with the required sequence of 12 '1'-bits
    /// (`0xfff`).
    BadSyncWord(u16),
    NotEnoughData {
        expected: usize,
        actual: usize,
    },
    /// The layer description used a reserved value
    BadLayerDescription,
    /// The frame_length field stored in the MPEG header is invalid as it holds a value smaller
    /// than the size of the header fields
    BadFrameLength {
        minimum: usize,
        actual: usize,
    },
}

/// Error indicating that not enough data was provided to `MpaHeader` to be able to extract the
/// whole MPEG payload following the header fields.
#[derive(Debug, PartialEq)]
pub struct PayloadError {
    /// None: The frame size is not possible to calculate due to invalid bit rate or sample rate
    pub expected: Option<usize>,
    pub actual: usize,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum MpegVersion {
    Mpeg1,
    Mpeg2,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum MpegLayer {
    LayerI,
    LayerII,
    LayerIII,
}

impl MpegLayer {
    /// The number of samples per frame is constant for each layer
    pub fn samples_per_frame(&self) -> u16 {
        match self {
            MpegLayer::LayerI => 384,
            MpegLayer::LayerII | MpegLayer::LayerIII => 1152,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ProtectionIndicator {
    CrcPresent,
    CrcAbsent,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum BitRate {
    BitRateFree, // TODO: Check standards
    BitRate8000,
    BitRate16000,
    BitRate24000,
    BitRate32000,
    BitRate40000,
    BitRate48000,
    BitRate56000,
    BitRate64000,
    BitRate80000,
    BitRate96000,
    BitRate112000,
    BitRate128000,
    BitRate144000,
    BitRate160000,
    BitRate176000,
    BitRate192000,
    BitRate224000,
    BitRate256000,
    BitRate288000,
    BitRate320000,
    BitRate352000,
    BitRate384000,
    BitRate416000,
    BitRate448000,
    BitRateReserved0xf, // TODO: Check standards
}

impl BitRate {
    fn from_index(version: MpegVersion, layer: MpegLayer, index: u8) -> BitRate {
        match (version, layer, index) {
            (_, _, 0x0) => BitRate::BitRateFree,

            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0x1) => BitRate::BitRate32000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0x2) => BitRate::BitRate64000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0x3) => BitRate::BitRate96000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0x4) => BitRate::BitRate128000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0x5) => BitRate::BitRate160000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0x6) => BitRate::BitRate192000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0x7) => BitRate::BitRate224000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0x8) => BitRate::BitRate256000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0x9) => BitRate::BitRate288000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0xa) => BitRate::BitRate320000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0xb) => BitRate::BitRate352000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0xc) => BitRate::BitRate384000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0xd) => BitRate::BitRate416000,
            (MpegVersion::Mpeg1, MpegLayer::LayerI, 0xe) => BitRate::BitRate448000,

            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0x1) => BitRate::BitRate32000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0x2) => BitRate::BitRate48000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0x3) => BitRate::BitRate56000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0x4) => BitRate::BitRate64000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0x5) => BitRate::BitRate80000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0x6) => BitRate::BitRate96000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0x7) => BitRate::BitRate112000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0x8) => BitRate::BitRate128000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0x9) => BitRate::BitRate160000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0xa) => BitRate::BitRate192000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0xb) => BitRate::BitRate224000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0xc) => BitRate::BitRate256000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0xd) => BitRate::BitRate320000,
            (MpegVersion::Mpeg1, MpegLayer::LayerII, 0xe) => BitRate::BitRate384000,

            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0x1) => BitRate::BitRate32000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0x2) => BitRate::BitRate40000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0x3) => BitRate::BitRate48000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0x4) => BitRate::BitRate56000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0x5) => BitRate::BitRate64000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0x6) => BitRate::BitRate80000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0x7) => BitRate::BitRate96000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0x8) => BitRate::BitRate112000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0x9) => BitRate::BitRate128000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0xa) => BitRate::BitRate160000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0xb) => BitRate::BitRate192000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0xc) => BitRate::BitRate224000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0xd) => BitRate::BitRate256000,
            (MpegVersion::Mpeg1, MpegLayer::LayerIII, 0xe) => BitRate::BitRate320000,

            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0x1) => BitRate::BitRate32000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0x2) => BitRate::BitRate48000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0x3) => BitRate::BitRate56000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0x4) => BitRate::BitRate64000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0x5) => BitRate::BitRate80000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0x6) => BitRate::BitRate96000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0x7) => BitRate::BitRate112000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0x8) => BitRate::BitRate128000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0x9) => BitRate::BitRate144000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0xa) => BitRate::BitRate160000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0xb) => BitRate::BitRate176000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0xc) => BitRate::BitRate192000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0xd) => BitRate::BitRate224000,
            (MpegVersion::Mpeg2, MpegLayer::LayerI, 0xe) => BitRate::BitRate256000,

            (MpegVersion::Mpeg2, _, 0x1) => BitRate::BitRate8000,
            (MpegVersion::Mpeg2, _, 0x2) => BitRate::BitRate16000,
            (MpegVersion::Mpeg2, _, 0x3) => BitRate::BitRate24000,
            (MpegVersion::Mpeg2, _, 0x4) => BitRate::BitRate32000,
            (MpegVersion::Mpeg2, _, 0x5) => BitRate::BitRate40000,
            (MpegVersion::Mpeg2, _, 0x6) => BitRate::BitRate48000,
            (MpegVersion::Mpeg2, _, 0x7) => BitRate::BitRate56000,
            (MpegVersion::Mpeg2, _, 0x8) => BitRate::BitRate64000,
            (MpegVersion::Mpeg2, _, 0x9) => BitRate::BitRate80000,
            (MpegVersion::Mpeg2, _, 0xa) => BitRate::BitRate96000,
            (MpegVersion::Mpeg2, _, 0xb) => BitRate::BitRate112000,
            (MpegVersion::Mpeg2, _, 0xc) => BitRate::BitRate128000,
            (MpegVersion::Mpeg2, _, 0xd) => BitRate::BitRate144000,
            (MpegVersion::Mpeg2, _, 0xe) => BitRate::BitRate160000,

            (_, _, 0xf) => BitRate::BitRateReserved0xf,
            _ => panic!(
                "invalid index {:#x} when parsing SamplingFrequency, expected a 2 bit index",
                index
            ),
        }
    }

    pub fn rate(self) -> Option<u32> {
        match self {
            BitRate::BitRateFree => None,

            BitRate::BitRate8000 => Some(8000),
            BitRate::BitRate16000 => Some(16000),
            BitRate::BitRate24000 => Some(24000),
            BitRate::BitRate32000 => Some(32000),
            BitRate::BitRate40000 => Some(40000),
            BitRate::BitRate48000 => Some(48000),
            BitRate::BitRate56000 => Some(56000),
            BitRate::BitRate64000 => Some(64000),
            BitRate::BitRate80000 => Some(80000),
            BitRate::BitRate96000 => Some(96000),
            BitRate::BitRate112000 => Some(112000),
            BitRate::BitRate128000 => Some(128000),
            BitRate::BitRate144000 => Some(144000),
            BitRate::BitRate160000 => Some(160000),
            BitRate::BitRate176000 => Some(176000),
            BitRate::BitRate192000 => Some(192000),
            BitRate::BitRate224000 => Some(224000),
            BitRate::BitRate256000 => Some(256000),
            BitRate::BitRate288000 => Some(288000),
            BitRate::BitRate320000 => Some(320000),
            BitRate::BitRate352000 => Some(352000),
            BitRate::BitRate384000 => Some(384000),
            BitRate::BitRate416000 => Some(416000),
            BitRate::BitRate448000 => Some(448000),

            BitRate::BitRateReserved0xf => None,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SamplingFrequency {
    /// 48kHz
    Freq48000,
    /// 44.1kHz
    Freq44100,
    /// 32kHz
    Freq32000,
    /// 24kHz
    Freq24000,
    /// 22.05kHz
    Freq22050,
    /// 16kHz
    Freq16000,
    FreqReserved0x3,
}

impl SamplingFrequency {
    fn from_index(version: MpegVersion, index: u8) -> SamplingFrequency {
        match (version, index) {
            (MpegVersion::Mpeg1, 0x0) => SamplingFrequency::Freq44100,
            (MpegVersion::Mpeg1, 0x1) => SamplingFrequency::Freq48000,
            (MpegVersion::Mpeg1, 0x2) => SamplingFrequency::Freq32000,
            (MpegVersion::Mpeg2, 0x0) => SamplingFrequency::Freq22050,
            (MpegVersion::Mpeg2, 0x1) => SamplingFrequency::Freq24000, // TODO: double check - really no 48000Hz etc in MPEG2?
            (MpegVersion::Mpeg2, 0x2) => SamplingFrequency::Freq16000,
            (_, 0x03) => SamplingFrequency::FreqReserved0x3,
            _ => panic!(
                "invalid index {:#x} when parsing SamplingFrequency, expected a 2 bit index",
                index
            ),
        }
    }

    pub fn freq(self) -> Option<u32> {
        match self {
            SamplingFrequency::Freq48000 => Some(48000),
            SamplingFrequency::Freq44100 => Some(44100),
            SamplingFrequency::Freq32000 => Some(32000),
            SamplingFrequency::Freq24000 => Some(24000),
            SamplingFrequency::Freq22050 => Some(22050),
            SamplingFrequency::Freq16000 => Some(16000),
            SamplingFrequency::FreqReserved0x3 => None,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Padding {
    Absent,
    Present,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ChannelMode {
    Stereo = 0x0,
    JointStereo = 0x1,
    DualChannel = 0x2,
    Mono = 0x3,
}

impl From<u8> for ChannelMode {
    fn from(value: u8) -> ChannelMode {
        match value {
            0x0 => ChannelMode::Stereo,
            0x1 => ChannelMode::JointStereo,
            0x2 => ChannelMode::DualChannel,
            0x3 => ChannelMode::Mono,
            _ => panic!(
                "invalid value {:#x} when parsing ChannelMode, expected a 2 bit value",
                value
            ),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Copyright {
    Absent = 0x0,
    Copyrighted = 0x1,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Originality {
    Original = 0x0,
    Copy = 0x1,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Emphasis {
    /// No emphasis
    EmphasisNone = 0x0,
    /// 50/15 ms
    Emphasis5015Ms = 0x1,
    EmphasisReserved0x2 = 0x2,
    /// CCIT J.17
    EmphasisCCITJ17 = 0x3,
}

impl From<u8> for Emphasis {
    fn from(value: u8) -> Emphasis {
        match value {
            0x0 => Emphasis::EmphasisNone,
            0x1 => Emphasis::Emphasis5015Ms,
            0x2 => Emphasis::EmphasisReserved0x2,
            0x3 => Emphasis::EmphasisCCITJ17,
            _ => panic!(
                "invalid value {:#x} when parsing Emphasis, expected a 2 bit value",
                value
            ),
        }
    }
}

/// Extract information for a single MPEG frame from the start of the given byte buffer .
pub struct MpaHeader<'buf> {
    buf: &'buf [u8],
}
impl<'buf> MpaHeader<'buf> {
    /// Construct an instance by borrowing the given byte buffer.  The given buffer may be longer
    /// then the MPEG frame, in which case the rest of the buffer is ignored.
    ///
    ///
    /// Note that this function returns `Err` if there is not enough data to parse the whole
    /// header, but it can return `Ok` even if there is not enough data in the given buffer to hold
    /// the whole of the payload that the header indicates should be present (however _if_ there is
    /// not enough data to hold the payload, then [`payload()`](#method.payload) will return
    /// `None`).
    pub fn from_bytes(buf: &'buf [u8]) -> Result<MpaHeader<'_>, MpaHeaderError> {
        assert!(!buf.is_empty());
        let header_len = 4;
        Self::check_len(header_len, buf.len())?;
        let header = MpaHeader { buf };
        if header.sync_word() != 0xfff {
            return Err(MpaHeaderError::BadSyncWord(header.sync_word()));
        }
        let crc_len = 2;
        if header.protection() == ProtectionIndicator::CrcPresent {
            Self::check_len(header_len + crc_len, buf.len())?;
        }
        if !header.valid_mpeg_layer() {
            return Err(MpaHeaderError::BadLayerDescription);
        }
        Ok(header)
    }

    fn check_len(expected: usize, actual: usize) -> Result<(), MpaHeaderError> {
        if actual < expected {
            Err(MpaHeaderError::NotEnoughData { expected, actual })
        } else {
            Ok(())
        }
    }

    fn header_length(&self) -> u16 {
        let fixed_len = 4;
        if self.protection() == ProtectionIndicator::CrcPresent {
            fixed_len + 2
        } else {
            fixed_len
        }
    }

    fn sync_word(&self) -> u16 {
        u16::from(self.buf[0]) << 4 | u16::from(self.buf[1] >> 4)
    }

    pub fn mpeg_version(&self) -> MpegVersion {
        if self.buf[1] & 0b0000_1000 != 0 {
            MpegVersion::Mpeg1
        } else {
            MpegVersion::Mpeg2
        }
    }

    fn valid_mpeg_layer(&self) -> bool {
        self.buf[1] & 0b0000_0110 != 0
    }

    pub fn mpeg_layer(&self) -> MpegLayer {
        match self.buf[1] & 0b0000_0110 {
            0b0000_0010 => MpegLayer::LayerIII,
            0b0000_0100 => MpegLayer::LayerII,
            0b0000_0110 => MpegLayer::LayerI,
            _ => panic!("Invalid MPEG layer in header"),
        }
    }

    pub fn protection(&self) -> ProtectionIndicator {
        if self.buf[1] & 0b0000_0001 != 0 {
            ProtectionIndicator::CrcAbsent
        } else {
            ProtectionIndicator::CrcPresent
        }
    }

    pub fn bit_rate(&self) -> BitRate {
        BitRate::from_index(self.mpeg_version(), self.mpeg_layer(), self.buf[2] >> 4)
    }

    pub fn sampling_frequency(&self) -> SamplingFrequency {
        SamplingFrequency::from_index(self.mpeg_version(), self.buf[2] >> 2 & 0b11)
    }

    pub fn padding(&self) -> Padding {
        if self.buf[2] & 0b0000_0010 != 0 {
            Padding::Present
        } else {
            Padding::Absent
        }
    }

    /// either 1 or 0
    pub fn private_bit(&self) -> u8 {
        self.buf[2] & 1
    }

    pub fn channel_mode(&self) -> ChannelMode {
        ChannelMode::from(self.buf[3] >> 6)
    }

    // TODO: missing mode extension

    pub fn copyright(&self) -> Copyright {
        if self.buf[3] & 0b0000_1000 != 0 {
            Copyright::Absent
        } else {
            Copyright::Copyrighted
        }
    }

    pub fn originality(&self) -> Originality {
        if self.buf[3] & 0b0000_0100 != 0 {
            Originality::Copy
        } else {
            Originality::Original
        }
    }

    pub fn emphasis(&self) -> Emphasis {
        Emphasis::from(self.buf[3] & 0b11)
    }

    /// length of this frame in bytes, including the length of the header,
    /// or None if it can't be calculated due to invalid bit rate or frame rate.
    pub fn frame_length(&self) -> Option<u16> {
        let padding_slots = match self.padding() {
            Padding::Absent => 0,
            Padding::Present => 1,
        };

        Some(if self.mpeg_layer() == MpegLayer::LayerI {
            ((12 * self.bit_rate().rate()? / self.sampling_frequency().freq()? + padding_slots) * 4)
                as u16
        } else {
            (144 * self.bit_rate().rate()? / self.sampling_frequency().freq()? + padding_slots)
                as u16
        })
    }

    /// Get the number of samples of this frame
    pub fn frame_samples(&self) -> u16 {
        self.mpeg_layer().samples_per_frame()
    }

    /// Calculates the length of the frame payload in bytes.
    /// Returns None if it can't be calculated due to invalid bit rate or frame rate.
    pub fn payload_length(&self) -> Option<u16> {
        Some(self.frame_length()? - self.header_length())
    }

    /// Gives the 16-bit cyclic redundancy check value stored in this frame header, or `None` if
    /// the header does not supply a CRC.
    ///
    /// NB the implementation doesn't currently check that the CRC is correct
    pub fn crc(&self) -> Option<u16> {
        match self.protection() {
            ProtectionIndicator::CrcAbsent => None,
            ProtectionIndicator::CrcPresent => {
                Some(u16::from(self.buf[4]) << 8 | u16::from(self.buf[5]))
            }
        }
    }

    /// The payload audio data inside this MPEG frame
    pub fn payload(&self) -> Result<&'buf [u8], PayloadError> {
        let Some(len) = self.frame_length() else {
            return Err(PayloadError { expected: None, actual: self.buf.len() })
        };
        let len = len as usize;
        if self.buf.len() < len {
            Err(PayloadError {
                expected: Some(len),
                actual: self.buf.len(),
            })
        } else {
            Ok(&self.buf[self.header_length() as usize..len])
        }
    }
}
impl<'buf> fmt::Debug for MpaHeader<'buf> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("MpaHeader")
            .field("mpeg_version", &self.mpeg_version())
            .field("mpeg_layer", &self.mpeg_layer())
            .field("protection", &self.protection())
            .field("bit_rate", &self.bit_rate())
            .field("sampling_frequency", &self.sampling_frequency())
            .field("padding", &self.padding())
            .field("private_bit", &self.private_bit())
            .field("channel_mode", &self.channel_mode())
            .field("copyright", &self.copyright())
            .field("originality", &self.originality())
            .field("emphasis", &self.emphasis())
            .field("frame_length", &self.frame_length())
            .field("crc", &self.crc())
            .finish()
    }
}

#[derive(Debug, PartialEq)]
pub enum CopyrightIdErr {
    TooFewBits,
    TooManyBits,
}

#[derive(Debug, PartialEq)]
pub struct CopyrightIdentification {
    pub copyright_identifier: u8,
    pub copyright_number: u64,
}

#[derive(PartialEq)]
enum MpaState {
    Start,
    Incomplete,
    Error,
}

#[derive(Debug, PartialEq)]
pub enum MpaParseError {
    BadSyncWord,
    BadLayerDescription,
    UnknownFrameLength,
    BadFrameLength,
}

/// Trait to be implemented by types that wish to consume the MPEG data produced by [`MpaParser`](struct.MpaParser.html).
///
/// # Example
///
/// ```rust
/// use mpa_reader::*;
///
/// struct MyConsumer { }
/// impl MpaConsumer for MyConsumer {
///     fn new_config(&mut self, mpeg_version: MpegVersion, mpeg_layer: MpegLayer, protection: ProtectionIndicator, rate: BitRate, freq: SamplingFrequency, private_bit: u8, channel_mode: ChannelMode, copyright: Copyright, originality: Originality, emphasis: Emphasis) {
///         println!("Configuration {:?} {:?} {:?} {:?} {:?}", mpeg_version, mpeg_layer, rate, freq, channel_mode);
///     }
///     fn payload(&mut self, header: &MpaHeader, buf: &[u8]) {
///         println!(" - frame of {} bytes with header {:?}", buf.len(), header);
///     }
///     fn error(&mut self, err: MpaParseError) {
///         println!(" - oops: {:?}", err);
///     }
/// }
///
/// let consumer = MyConsumer { };
/// let parser = MpaParser::new(consumer);
/// ```
pub trait MpaConsumer {
    /// Called when a new configuration is found within the MPEG bitstream
    ///
    /// An MPEG bitstream should have the same configuration throughout, so this would usually just
    /// be called once at the beginning of the stream.  The audio configuration header values do
    /// however appear in every frame (so that the bitstream format can support seeking, not that
    /// this implementation helps there) and so it would be possible for a malformed bitstream to
    /// signal a configuration change part way through.
    ///
    #[allow(clippy::too_many_arguments)]
    fn new_config(
        &mut self,
        mpeg_version: MpegVersion,
        layer: MpegLayer,
        protection: ProtectionIndicator,
        rate: BitRate,
        freq: SamplingFrequency,
        private_bit: u8,
        channel_mode: ChannelMode,
        copyright: Copyright,
        originality: Originality,
        emphasis: Emphasis,
    );

    /// called with the MPEG frame payload
    fn payload(&mut self, header: &MpaHeader, buf: &[u8]);

    /// called if MpaParser encounters an error in the MPEG bitstream.
    fn error(&mut self, err: MpaParseError);
}

/// Find MPEG frames within provided buffers of data, announcing audio configuration as it is
/// discovered (normally just once at the start, but possibly changing during the stream if the
/// stream is malformed).
///
/// Does not currently try to handle re-synchronise with the MPEG bitstream on encountering bad
/// data.
pub struct MpaParser<C>
where
    C: MpaConsumer,
{
    pub consumer: C,
    current_config: [u8; 3],
    state: MpaState,
    incomplete_frame: Vec<u8>,
    desired_data_len: Option<usize>,
}
impl<C> MpaParser<C>
where
    C: MpaConsumer,
{
    pub fn new(consumer: C) -> MpaParser<C> {
        MpaParser {
            consumer,
            current_config: [0; 3], // TODO: track all 4 bytes? (compare with ADTS first 3 bytes)
            state: MpaState::Start,
            incomplete_frame: vec![],
            desired_data_len: None,
        }
    }

    fn is_new_config(&self, header_data: &[u8]) -> bool {
        self.current_config != header_data[0..3]
    }

    fn remember(&mut self, remaining_data: &[u8], desired_data_len: usize) {
        self.state = MpaState::Incomplete;
        self.incomplete_frame.clear();
        self.incomplete_frame.extend_from_slice(remaining_data);
        self.desired_data_len = Some(desired_data_len);
    }

    /// Initialize or re-initialize parser state.  Call this function before processing a group of
    /// MPEG frames to ensure that any error state due to processing an earlier group of MPEG
    /// frames is cleared.
    pub fn start(&mut self) {
        if self.state == MpaState::Incomplete {
            self.incomplete_frame.clear();
            self.desired_data_len = None;
            eprintln!("MPEG: incomplete data buffer dropped by call to start()");
        }
        self.state = MpaState::Start;
    }

    /// Extracts information about each MPEG frame in the given buffer, which is passed to the
    /// `MpaConsumer` implementation supplied at construction time.
    ///
    /// If the given buffer ends part-way through an MPEG frame, the remaining unconsumed data
    /// will be buffered inside this MpaParser instance, and the rest of the MPEG frame may be
    /// passed in another buffer in the next call to this method.
    pub fn push(&mut self, mpa_buf: &[u8]) {
        let mut buf = mpa_buf;
        match self.state {
            MpaState::Error => return, // TODO: resync to recover from bitstream errors
            MpaState::Incomplete => {
                // on last call to push(), the end of the mpa_buf held the start of an MPEG
                // frame, and we copied that data into incomplete_buffer, so now lets try to add
                // enough initial bytes from the mpa_buf given to this call to get a complete
                // frame
                loop {
                    let bytes_needed_to_complete_frame =
                        self.desired_data_len.unwrap() - self.incomplete_frame.len();
                    if buf.len() < bytes_needed_to_complete_frame {
                        self.incomplete_frame.extend_from_slice(buf);
                        return;
                    }
                    self.incomplete_frame
                        .extend_from_slice(&buf[..bytes_needed_to_complete_frame]);
                    buf = &buf[bytes_needed_to_complete_frame..];
                    let mut still_more = false; // TODO: this is horrible
                    match MpaHeader::from_bytes(&self.incomplete_frame[..]) {
                        Ok(header) => {
                            let Some(frame_length) = header.frame_length() else {
                                self.consumer.error(MpaParseError::UnknownFrameLength);
                                return;
                            };
                            if (frame_length as usize) > self.incomplete_frame.len() {
                                self.desired_data_len = Some(frame_length as usize);
                                still_more = true;
                            } else {
                                if self.is_new_config(&self.incomplete_frame[..]) {
                                    Self::push_config(
                                        &mut self.current_config,
                                        &mut self.consumer,
                                        &header,
                                        &self.incomplete_frame[..],
                                    );
                                }
                                Self::push_payload(&mut self.consumer, header);
                                self.state = MpaState::Start;
                            }
                        }
                        Err(e) => {
                            self.state = MpaState::Error;
                            match e {
                                MpaHeaderError::BadSyncWord { .. } => {
                                    self.consumer.error(MpaParseError::BadSyncWord);
                                    return;
                                }
                                MpaHeaderError::BadLayerDescription { .. } => {
                                    self.consumer.error(MpaParseError::BadLayerDescription);
                                    return;
                                }
                                MpaHeaderError::BadFrameLength { .. } => {
                                    self.consumer.error(MpaParseError::BadFrameLength);
                                    return;
                                }
                                MpaHeaderError::NotEnoughData { expected, .. } => {
                                    self.desired_data_len = Some(expected);
                                    still_more = true;
                                }
                            }
                        }
                    }
                    if !still_more {
                        break;
                    }
                }
            }
            MpaState::Start => (),
        };
        let mut pos = 0;
        while pos < buf.len() {
            let remaining_data = &buf[pos..];
            let h = match MpaHeader::from_bytes(remaining_data) {
                Ok(header) => header,
                Err(e) => {
                    self.state = MpaState::Error;
                    match e {
                        MpaHeaderError::BadSyncWord { .. } => {
                            self.consumer.error(MpaParseError::BadSyncWord)
                        }
                        MpaHeaderError::BadLayerDescription { .. } => {
                            self.consumer.error(MpaParseError::BadLayerDescription);
                            return;
                        }
                        MpaHeaderError::BadFrameLength { .. } => {
                            self.consumer.error(MpaParseError::BadFrameLength);
                            return;
                        }
                        MpaHeaderError::NotEnoughData { expected, .. } => {
                            self.remember(remaining_data, expected);
                            return;
                        }
                    }
                    return;
                }
            };
            let Some(frame_length) = h.frame_length() else {
                self.consumer.error(MpaParseError::UnknownFrameLength);
                return;
            };
            let new_pos = pos + frame_length as usize;
            if new_pos > buf.len() {
                self.remember(remaining_data, frame_length as usize);
                return;
            }
            if self.is_new_config(remaining_data) {
                Self::push_config(
                    &mut self.current_config,
                    &mut self.consumer,
                    &h,
                    remaining_data,
                );
            }
            Self::push_payload(&mut self.consumer, h);
            self.state = MpaState::Start;
            pos = new_pos;
        }
    }

    fn push_config(
        current_config: &mut [u8; 3],
        consumer: &mut C,
        h: &MpaHeader<'_>,
        frame_buffer: &[u8],
    ) {
        current_config.copy_from_slice(&frame_buffer[0..3]);
        consumer.new_config(
            h.mpeg_version(),
            h.mpeg_layer(),
            h.protection(),
            h.bit_rate(),
            h.sampling_frequency(),
            h.private_bit(),
            h.channel_mode(),
            h.copyright(),
            h.originality(),
            h.emphasis(),
        );
    }

    fn push_payload(consumer: &mut C, h: MpaHeader<'_>) {
        match h.payload() {
            Ok(payload) => {
                consumer.payload(&h, payload);
            }
            Err(PayloadError { expected: None, .. }) => {
                panic!("Header doesn't contain enough information to compute payload length");
            }
            Err(PayloadError {
                expected: Some(expected),
                actual,
            }) => {
                // since we checked we had enough data for the whole frame above, this must be
                // a bug,
                panic!(
                    "Unexpected payload size mismatch: expected {}, actual size {}",
                    expected, actual
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitstream_io::{BigEndian, BitWrite, BitWriter, BE};
    use std::io;

    fn make_test_data<F>(builder: F) -> Vec<u8>
    where
        F: Fn(BitWriter<&mut Vec<u8>, BE>) -> Result<(), io::Error>,
    {
        let mut data: Vec<u8> = Vec::new();
        builder(BitWriter::endian(&mut data, BigEndian)).unwrap();
        data
    }

    fn write_frame(w: &mut BitWriter<&mut Vec<u8>, BE>) -> Result<(), io::Error> {
        w.write(12, 0xfff)?; // sync_word
        w.write(1, 0b0)?; // mpeg_version
        w.write(2, 0b10)?; // layer
        w.write(1, 1)?; // protection_absent

        w.write(4, 0b1100)?; // bitrate index
        w.write(2, 0b01)?; // sampling_frequency_index
        w.write(1, 0)?; // padding_bit
        w.write(1, 1)?; // private_bit

        w.write(2, 0b00)?; // channel_mode
        w.write(2, 0b00)?; // mode_extension (only joint stereo)
        w.write(1, 1)?; // copyright
        w.write(1, 1)?; // original_copy
        w.write(2, 0b00)?; // emphasis

        for _ in 0..764 {
            w.write(8, 0b10000001)?; // 1 byte of payload data
        }

        Ok(())
    }

    #[test]
    fn no_crc() {
        let header_data = make_test_data(|mut w| write_frame(&mut w));
        let header = MpaHeader::from_bytes(&header_data[..]).unwrap();
        assert_eq!(header.mpeg_version(), MpegVersion::Mpeg2);
        assert_eq!(header.mpeg_layer(), MpegLayer::LayerII);
        assert_eq!(header.protection(), ProtectionIndicator::CrcAbsent);
        assert_eq!(header.bit_rate(), BitRate::BitRate128000);
        assert_eq!(header.bit_rate().rate(), Some(128000));
        assert_eq!(header.sampling_frequency(), SamplingFrequency::Freq24000);
        assert_eq!(header.sampling_frequency().freq(), Some(24000));
        assert_eq!(header.padding(), Padding::Absent);
        assert_eq!(header.private_bit(), 1);
        assert_eq!(header.channel_mode(), ChannelMode::Stereo);
        assert_eq!(header.originality(), Originality::Copy);
        assert_eq!(header.emphasis(), Emphasis::EmphasisNone);
        assert_eq!(header.frame_length(), Some(764 + 4));
        assert_eq!(header.payload_length(), Some(764));
        assert_eq!(header.payload().unwrap()[0], 0b10000001);
        assert_eq!(header.payload().unwrap().len(), 764);
    }

    struct MockConsumer {
        seq: usize,
        payload_seq: usize,
        payload_size: Option<usize>,
    }
    impl MockConsumer {
        pub fn new() -> MockConsumer {
            MockConsumer {
                seq: 0,
                payload_seq: 0,
                payload_size: None,
            }
        }
        pub fn assert_seq(&mut self, expected: usize) {
            assert_eq!(expected, self.seq);
            self.seq += 1;
        }
    }
    impl MpaConsumer for MockConsumer {
        // TODO: assertions are terribly brittle
        fn new_config(
            &mut self,
            mpeg_version: MpegVersion,
            _mpeg_layer: MpegLayer,
            _protection: ProtectionIndicator,
            _rate: BitRate,
            _freq: SamplingFrequency,
            _private_bit: u8,
            _channel_mode: ChannelMode,
            _copyright: Copyright,
            _originality: Originality,
            _emphasis: Emphasis,
        ) {
            self.assert_seq(0);
            assert_eq!(mpeg_version, MpegVersion::Mpeg2);
        }
        fn payload(&mut self, _header: &MpaHeader, buf: &[u8]) {
            self.payload_seq += 1;
            let new_payload_seq = self.payload_seq;
            self.assert_seq(new_payload_seq);
            self.payload_size = Some(buf.len());
        }
        fn error(&mut self, err: MpaParseError) {
            panic!("no errors expected in bitstream: {:?}", err);
        }
    }

    #[test]
    fn parser() {
        let header_data = make_test_data(|mut w| {
            write_frame(&mut w)?;
            write_frame(&mut w)
        });
        for split in 0..header_data.len() {
            let mut parser = MpaParser::new(MockConsumer::new());
            let (head, tail) = header_data.split_at(split);
            parser.push(head);
            parser.push(tail);
            assert_eq!(2, parser.consumer.payload_seq);
            assert_eq!(Some(764), parser.consumer.payload_size);
        }
    }

    #[test]
    fn too_short() {
        let header_data = make_test_data(|mut w| write_frame(&mut w));
        let mut parser = MpaParser::new(MockConsumer::new());
        parser.push(&header_data[..3]);
        parser.push(&header_data[3..4]);
    }
}
