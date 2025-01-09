/**
 * Copyright 2025 The MITRE Corporation

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

use std::collections::HashMap;
use std::vec;

use nom::bytes::complete::{is_a, is_not};
use nom::character::complete::{char, multispace0, space0, space1};
use nom::combinator::{map, opt};
use nom::error::{context, VerboseError, VerboseErrorKind};
use nom::multi::{many0, many1};
use nom::sequence::{delimited, terminated, tuple};
use nom::IResult;
use serde::{Deserialize, Serialize};

use crate::errors::{pretty_print_error, ILFParseError};
use crate::ilf_attributes::{parse_attrs, Numeric, Value};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Log {
    pub log_type: String,
    pub src: String,
    pub dest: String,
    pub timestamp: String,
    pub fields: Vec<String>,
    pub attributes: HashMap<String, Value>,
}

impl Log {
    pub fn get_id(&self) -> i32 {
        let val = self
            .attributes
            .get("_hblID")
            .expect("expecting _hblID attribute to be present");
        use Value::*;
        match val {
            VNum(Numeric::Int(id)) => *id,
            _ => panic!("expecting _hblID to be Integer"),
        }
    }

    pub fn new_with_timestamp(
        log_type: String,
        src: String,
        dest: String,
        fields: Vec<String>,
        attrs: HashMap<String, Value>,
    ) -> Self {
        Log {
            log_type,
            src,
            dest,
            timestamp: chrono::Local::now().to_rfc3339(),
            fields,
            attributes: attrs,
        }
    }
    pub fn new(
        log_type: String,
        src: String,
        dest: String,
        timestamp: String,
        fields: Vec<String>,
        attrs: HashMap<String, Value>,
    ) -> Self {
        Log {
            log_type,
            src,
            dest,
            timestamp,
            fields,
            attributes: attrs,
        }
    }

    pub fn new_from_attributes(
        log_type: String,
        src: Option<String>,
        dest: Option<String>,
        timestamp: Option<String>,
        fields: Vec<String>,
        attrs: Vec<(String, Value)>,
    ) -> Log {
        Log {
            log_type,
            src: src.unwrap_or(String::from("*")),
            dest: dest.unwrap_or(String::from("*")),
            timestamp: timestamp.unwrap_or_else(|| chrono::Local::now().to_rfc3339()),
            fields: fields,
            attributes: HashMap::from_iter(attrs.into_iter()),
        }
    }
}

impl From<(&str, &[(&str, &str)])> for Log {
    fn from(value: (&str, &[(&str, &str)])) -> Self {
        let (log_type, attrs) = value;
        Log {
            log_type: log_type.to_string(),
            src: "*".to_string(),
            dest: "*".to_string(),
            timestamp: chrono::Local::now().to_rfc3339(),
            fields: Default::default(),
            attributes: HashMap::from_iter(
                attrs
                    .into_iter()
                    .map(|(name, val)| (name.to_string(), Value::VString(val.to_string()))),
            ),
        }
    }
}

fn serialize_ilf_string(string: &str) -> String {
    // preallocate minimum space (just the original string
    // plus room for quotes, assuming no escape characters are needed)
    let mut out_str = String::with_capacity(string.len() + 2);

    out_str.push('"');
    for c in string.chars() {
        match c {
            '\\' => out_str.push_str("\\\\"),
            '"' => out_str.push_str("\\\""),
            _ => out_str.push(c),
        };
    }
    out_str.push('"');

    out_str
}

impl std::fmt::Display for Log {
    fn fmt(&self, w: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            w,
            "{}[{},{},{},(",
            self.log_type, self.src, self.dest, self.timestamp
        )?;

        for (key, value) in self.attributes.iter() {
            match value {
                Value::VArray(a) => {
                    write!(w, "{}=[", key)?;
                    let mut iter = a.iter().peekable();
                    while let Some(n) = iter.next() {
                        write!(w, "{}", n)?;
                        if iter.peek().is_some() {
                            write!(w, ",")?;
                        }
                    }
                    write!(w, "];")?;
                }

                Value::VNum(n) => write!(w, "{}={};", key, n)?,
                Value::VString(string) => write!(w, "{}={};", key, serialize_ilf_string(string))?,
                Value::VBoolean(bool) => write!(w, "{}={};", key, bool)?,
                Value::VNone => write!(w, "{}=;", key)?,
            }
        }

        // note trailing whitespace
        write!(w, ")] ")?;

        Ok(())
    }
}

/// This type helps us use custom verbose errors
pub type Res<T, U> = IResult<T, U, VerboseError<T>>;
/// This is the type of each parsed single log
type ParseResult<'a> = (
    &'a str,                        // Log Type
    &'a str,                        // Src
    &'a str,                        // Dest
    &'a str,                        // Timestamp
    Vec<Option<&'a str>>,           // all other fields
    Option<HashMap<String, Value>>, // Attributes
    (),                             // Closing brace, ignored
);

/// Convert the result of ILF parsing into the log struct
///  This method is kept separate so ILF validation logic can occur
fn parse_result_to_log(log: ParseResult) -> Result<Log, &str> {
    let (log_type, src, dest, timestamp, fields, attributes, _) = log;

    // Validate ILF

    // Return log
    Ok(Log {
        log_type: log_type.to_string(),
        src: src.to_string(),
        dest: dest.to_string(),
        timestamp: timestamp.to_string(),
        fields: fields.iter().map(|o| o.unwrap_or("").to_string()).collect(),
        attributes: attributes.unwrap_or_default(),
    })
}

/// Parses a single ILF
fn parse_single_log(input: &str) -> Res<&str, ParseResult> {
    let (rest, (log, src, dst, time, fields, attrs, close)) = tuple((
        context("ilf_name", parse_log_type),
        context("src field", src_dst_token),
        context("dst field", src_dst_token),
        context("timestamp field", timestamp),
        context("other fields", many0(timestamp)),
        context("attributes", opt(parse_attrs)),
        context("close brace", parse_close_brace),
    ))(input)?;
    Ok((
        rest,
        (log, src, dst, time.unwrap_or(""), fields, attrs, close),
    ))
}

/// Parses a string of ILF logs.
///  If errors occur, returns a nicely-formatted error message
pub fn parse_logs(input: &str) -> anyhow::Result<(&str, Vec<Log>), ILFParseError> {
    let mut logs: Vec<Log> = Vec::new();

    // Parse entire string
    let res: Res<&str, Vec<ParseResult>> =
        context("ILFs", many1(terminated(parse_single_log, multispace0)))(input);
    match res {
        Ok((rest, log_vec)) if rest.trim().is_empty() => {
            for log in log_vec {
                logs.push(match parse_result_to_log(log) {
                    Ok(l) => l,
                    Err(s) => {
                        return Err(ILFParseError {
                            parse_error: s.to_string(),
                            ilf: input.to_string(),
                        });
                    }
                })
            }
            Ok((rest, logs))
        }
        Ok((rest, _log_vec)) => match parse_single_log(rest) {
            Ok(_) => Err(ILFParseError {
                parse_error: format!(
                    "ILF {} didn't parse during first pass, but parsed during second pass.",
                    rest
                ),
                ilf: rest.to_string(),
            }),
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(ILFParseError {
                parse_error: pretty_print_error(rest, e),
                ilf: input.to_string(),
            }),
            Err(e) => Err(ILFParseError {
                parse_error: e.to_string(),
                ilf: input.to_string(),
            }),
        },
        // If there's an error, use the custom conversion to format the error object nicely
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(ILFParseError {
            parse_error: pretty_print_error(input, e),
            ilf: input.to_string(),
        }),
        // If there's an error we can't format just turn it into a string
        Err(e) => Err(ILFParseError {
            parse_error: e.to_string(),
            ilf: input.to_string(),
        }),
    }
}

/// parse a single ILF from a string
pub fn parse_log_to_tuple(input: &str) -> anyhow::Result<(&str, Log), ILFParseError> {
    // Parse one log
    let res: Res<&str, ParseResult> = context("ILF", parse_single_log)(input);
    match res {
        Ok((rest, log)) => match parse_result_to_log(log) {
            Ok(l) => Ok((rest, l)),
            Err(s) => Err(ILFParseError {
                parse_error: s.to_string(),
                ilf: input.to_string(),
            }),
        },
        // If there's an error, use the custom conversion to format the error object nicely
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(ILFParseError {
            parse_error: pretty_print_error(input, e),
            ilf: input.to_string(),
        }),
        // If there's an error we can't format just turn it into a string
        Err(e) => Err(ILFParseError {
            parse_error: e.to_string(),
            ilf: input.to_string(),
        }),
    }
}

/// Parse the name of the ILF log
fn parse_log_type(input: &str) -> Res<&str, &str> {
    // ILF name can only contain alphanumeric or _
    delimited(
        space0,
        is_a("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"),
        tuple((space0, char('['))),
    )(input)
}

/// Parse the source or destination field of an ILF
fn src_dst_token(input: &str) -> Res<&str, &str> {
    // Source/Destination can only contain alphanumeric or _ or *
    delimited(
        space0,
        is_a("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._*:-"),
        // Consume the ',' character
        tuple((space0, char(','))),
    )(input)
}

/// Parse the timestamp field of an ILF
fn timestamp(input: &str) -> Res<&str, Option<&str>> {
    // TODO detect integer vs ISO8601 and parse
    delimited(space0, opt(is_not(",;[]()")), tuple((space0, char(','))))(input)
}

/// consumes any remaining whitespace after final close brace
fn parse_close_brace(input: &str) -> Res<&str, ()> {
    // Check to see if we missed anything- if so, it's probably because the attributes field failed to parse
    //  and the parser is trying to end the ILF
    if let Ok((rest, _)) = tuple((space0::<&str, VerboseError<&str>>, char('(')))(input) {
        return IResult::Err(nom::Err::Error(VerboseError {
            errors: vec![(
                rest,
                VerboseErrorKind::Context("Attribute field not properly processed"),
            )],
        }));
    }

    // last space is MANDATORY!!!
    map(tuple((space0, char(']'), space1)), |_res| ())(input)
}
