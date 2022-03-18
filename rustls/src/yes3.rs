//! Ja3 fingerprint

use core::{
    fmt::{Display, Formatter, Write},
    str::FromStr,
};
use std::{result::Result, vec::Vec};

use crate::{
    msgs::enums::{ECPointFormat, ExtensionType, NamedGroup},
    CipherSuite, ProtocolVersion,
};

/// Error(s) that can show up when (de)serializing Ja3 fingerprints
#[derive(core::fmt::Debug)]
pub struct Error;

impl<T: std::error::Error> From<T> for Error {
    fn from(_: T) -> Self {
        Error
    }
}

// Utils
macro_rules! from_str {
    ($ty:path; $input:expr) => {
        match $input.is_empty() {
            true => Ok(Default::default()),
            _ => $input
                .split('-')
                .map(|x| <$ty>::from_str(x).map(Into::into))
                .collect(),
        }
    };
}
macro_rules! format_vec {
    ($fn:ident; $vec:expr; $f:ident) => {
        match $vec.len() {
            0 => {}
            1 => $vec[0].$fn().fmt($f)?,
            _ => {
                for x in &$vec[..$vec.len() - 1] {
                    x.$fn().fmt($f)?;
                    $f.write_char('-')?;
                }
                $vec[$vec.len() - 1].$fn().fmt($f)?;
            }
        }
    };
}

#[derive(core::cmp::PartialEq, Debug, Clone)]
/// Ja3 Client fingerprint
///
/// <https://github.com/salesforce/ja3>
pub struct Ja3 {
    /// SSL Version(s) - first part of the fingerprint
    pub ssl_versions: Vec<ProtocolVersion>,
    /// Cipher(s) - second part of the fingerprint
    pub ciphers: Vec<CipherSuite>,
    /// SSL Extension(s) - third part of the fingerprint
    pub ssl_extensions: Vec<ExtensionType>,
    /// Elliptic Curve(s) - fourth part of the fingerprint
    pub elliptic_curves: Vec<NamedGroup>,
    /// Elliptic Curve Point Format(s) - fifth part of the fingerprint
    pub elliptic_curve_point_formats: Vec<ECPointFormat>,
}

impl FromStr for Ja3 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut c = s.splitn(5, ',');
        let parts: [&str; 5] = <[(); 5]>::default().map(|_| c.next().unwrap_or(""));
        Ok(Self {
            ssl_versions: from_str!(u16; parts[0])?,
            ciphers: from_str!(u16; parts[1])?,
            ssl_extensions: from_str!(u16; parts[2])?,
            elliptic_curves: from_str!(u16; parts[3])?,
            elliptic_curve_point_formats: from_str!(u8; parts[4])?,
        })
    }
}

impl Display for Ja3 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        format_vec!(get_u16; self.ssl_versions; f);
        f.write_char(',')?;
        format_vec!(get_u16; self.ciphers; f);
        f.write_char(',')?;
        format_vec!(get_u16; self.ssl_extensions; f);
        f.write_char(',')?;
        format_vec!(get_u16; self.elliptic_curves; f);
        f.write_char(',')?;
        format_vec!(get_u8; self.elliptic_curve_point_formats;f);
        Ok(())
    }
}

/// Ja3 Server fingerprint
///
/// <https://github.com/salesforce/ja3>
pub struct Ja3S {
    /// SSL Version(s) - first part of the fingerprint
    pub ssl_versions: Vec<ProtocolVersion>,
    /// Cipher(s) - second part of the fingerprint
    pub ciphers: Vec<CipherSuite>,
    /// SSL Extension(s) - third part of the fingerprint
    pub ssl_extensions: Vec<ExtensionType>,
}

impl FromStr for Ja3S {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut c = s.splitn(5, ',');
        let parts: [&str; 3] = <[(); 3]>::default().map(|_| c.next().unwrap_or(""));
        Ok(Self {
            ssl_versions: from_str!(u16; parts[0])?,
            ciphers: from_str!(u16; parts[1])?,
            ssl_extensions: from_str!(u16; parts[2])?,
        })
    }
}

impl Display for Ja3S {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        format_vec!(get_u16;self.ssl_versions; f);
        f.write_char(',')?;
        format_vec!(get_u16;self.ciphers; f);
        f.write_char(',')?;
        format_vec!(get_u16; self.ssl_extensions; f);
        Ok(())
    }
}
