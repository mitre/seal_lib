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

use nom::branch::alt;
use nom::bytes::complete::tag_no_case;
use nom::bytes::complete::take_while1;
use nom::bytes::complete::{is_a, tag};
use nom::character::complete::{anychar, char, multispace0, space0};
use nom::combinator::{opt, recognize};
use nom::error::{context, convert_error, ErrorKind, VerboseError, VerboseErrorKind};
use nom::multi::many0;
use nom::number::complete::recognize_float;
use nom::sequence::{delimited, tuple};
use nom::IResult;
use ordered_float::OrderedFloat;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::vec;

use crate::ilf::Res;

/// Numeric type for wrapping different types of numeric values
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Numeric {
    Int(i32),
    Double(OrderedFloat<f64>),
    Long(i64),
}

impl From<f64> for Numeric {
    fn from(value: f64) -> Self {
        Self::Double(OrderedFloat(value))
    }
}

impl From<i64> for Numeric {
    fn from(value: i64) -> Self {
        Self::Long(value)
    }
}

impl From<i32> for Numeric {
    fn from(value: i32) -> Self {
        Self::Int(value)
    }
}

impl std::fmt::Display for Numeric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Numeric::Int(n) => write!(f, "{}", n),
            Numeric::Double(n) => write!(f, "{}", n),
            Numeric::Long(n) => write!(f, "{}", n),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    VArray(Vec<Numeric>),
    VNum(Numeric),
    VString(String),
    VBoolean(bool),
    VNone,
}

impl Default for Value {
    fn default() -> Self {
        Self::VNone
    }
}

impl TryFrom<String> for Value {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match parse_attr_val(value.as_str()) {
            Ok(("", val)) => Ok(val),
            Ok((leftover, _)) => Err(format!("Value wasn't parsed fully. leftover: {}", leftover)),
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(format!(
                "Failed to parse. {}",
                convert_error(value.as_str(), e)
            )),
            Err(nom::Err::Incomplete(e)) => Err(format!("Failed to parse. {:?}", e)),
        }
    }
}

/// Parse a attribute token
fn attr_token(input: &str) -> Res<&str, &str> {
    // Attribute tokens can only contain alphanumeric or _ or . or / or -
    // A token is a key or a identifier value
    let valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./";
    take_while1(|i| valid_chars.contains(i))(input)
}

/// Parse an attribute key
fn parse_attr_key(input: &str) -> Res<&str, &str> {
    delimited(space0, attr_token, tuple((space0, char('='))))(input)
}

/// Parse an attribute value
fn parse_attr_val(input: &str) -> Res<&str, Value> {
    // arrays start with [, Strings start with " or ', numbers and enums and bools are alphanumeric.
    let (rest, (value, semicolon)) = match tuple((
        space0,
        alt((
            context("none", parse_attr_val_empty),
            context("bool", parse_attr_val_bool),
            context("array", parse_attr_val_array),
            context("string", parse_attr_val_string),
            context("num", parse_attr_val_num),
            context("enum", parse_attr_val_enum),
        )),
        tuple((space0, opt(char(';')))),
    ))(input)
    {
        Err(e) => IResult::Err(match e {
            nom::Err::Error(e) => match &e.errors[..] {
                [(res, _verb_err), ..] if !res.is_empty() => {
                    let char = res.bytes().next().unwrap();
                    if !char.is_ascii() {
                        nom::Err::Failure(VerboseError {
                            errors: vec![(
                                *res,
                                VerboseErrorKind::Context(
                                    "Invalid character. Only ASCII characters are allowed outside of strings.",
                                ),
                            )],
                        })
                    } else {
                        nom::Err::Error(e)
                    }
                }
                _ => nom::Err::Error(e),
            },
            e => e,
        }),
        Ok((rest, (_, value, (_, semicolon)))) => IResult::Ok((rest, (value, semicolon))),
    }?;

    // IF we didn't find a semicolon to end the value, make sure we're not in a bad state
    if semicolon.is_none() {
        // Check if there's a close paren after the value
        if tuple((multispace0::<&str, VerboseError<&str>>, char(')')))(rest).is_err() {
            // If the character after a value ends isn't spaces followed by a semicolon or close paren, something is wrong.
            // Fail ILF parsing.
            return IResult::Err(nom::Err::Failure(VerboseError {
                errors: vec![(
                    rest,
                    VerboseErrorKind::Context("Value Ending when it shouldn't. Cannot continue."),
                )],
            }));
        }
    }

    Ok((rest, value))
}

/// Make sure we're reading the entire value, otherwise it's probably not what you're parsing it as, and the parser
///  should backtrack and try to parse it as something else.
/// Valid ways for a value to end:
/// - ; or ) means it was an attribute value
/// - , or ] means it was in an array
fn check_for_end_of_value(input: &str) -> Res<&str, ()> {
    if input.len() > 1
        && tuple((
            space0::<&str, VerboseError<&str>>,
            alt((char(';'), char(')'), char(','), char(']'))),
        ))(input)
        .is_err()
    {
        return IResult::Err(nom::Err::Error(VerboseError {
            errors: vec![(input, VerboseErrorKind::Nom(ErrorKind::IsNot))],
        }));
    };
    IResult::Ok((input, ()))
}

fn parse_attr_val_empty(input: &str) -> Res<&str, Value> {
    let (_, _) = context("Empty", char(';'))(input)?;
    // Don't progress reading
    Ok((input, Value::VNone))
}

fn parse_attr_val_bool(input: &str) -> Res<&str, Value> {
    let (rest, val) = context(
        "attr value bool",
        alt((tag_no_case("true"), tag_no_case("false"))),
    )(input)?;
    let bool = val.to_ascii_lowercase() == "true";
    Ok((rest, Value::VBoolean(bool)))
}

fn parse_attr_val_array(input: &str) -> Res<&str, Value> {
    let (rest, val) = context(
        "attr value array",
        delimited(char('['), many0(parse_array_item), char(']')),
    )(input)?;
    Ok((rest, Value::VArray(val)))
}

/// Attempts to parse an array item and strip away the delimiting commas
fn parse_array_item(input: &str) -> Res<&str, Numeric> {
    // TODO: should we add support for non-numbers in arrays?
    context(
        "Array item",
        delimited(space0, parse_ilf_number, tuple((space0, opt(char(','))))),
    )(input)
}

/// Generates a function for recognizing a number given a prefix and character set
fn recognize_prefixed_number<'a>(
    prefix: &'a str,
    valid_chars: &'a str,
) -> impl Fn(&'a str) -> Res<&'a str, (Option<char>, &str, &str)> {
    move |input: &'a str| {
        let (rest, num) = tuple((
            // parse the sign, if any
            context("sign", opt(alt((char('+'), char('-'))))),
            // parse the base prefix. If not present, number is invalid
            context("prefix", tag(prefix)),
            // parse the number. Uses recognize/map so the entire string is returned.
            recognize(tuple((context("digit with radix", is_a(valid_chars)),))),
        ))(input)?;

        // Make sure we've parsed the entire number
        check_for_end_of_value(rest)?;

        IResult::Ok((rest, num))
    }
}

/// Parses a number according to the rules in parse_number, but also checks to make sure the number is in a proper
///  location within an ILF record.
pub fn parse_ilf_number(input: &str) -> Res<&str, Numeric> {
    let (rest, numeric) = parse_number(input)?;
    // Make sure we've parsed the entire number
    check_for_end_of_value(rest)?;

    IResult::Ok((rest, numeric))
}

/// Parses a number in one of 4 forms:
/// - a binary string prefixed with 0b,
/// - an octal string prefixed with 0o,
/// - a hex string prefixed with 0x
/// - a valid base-10 float
///  - a base-10 float can consist of:
///   - an optional sign (+, -)
///   - Either:
///     - a number and an optional decimal point and optional number
///     - a decimal point and a mandatory number
///   - an exponent (e or E followed by a sign and a number)
pub fn parse_number(input: &str) -> Res<&str, Numeric> {
    // Try and read in the number
    let result = alt((
        context("binary", recognize_prefixed_number("0b", "01")),
        context("octal", recognize_prefixed_number("0o", "01234567")),
        context("hex", recognize_prefixed_number("0x", "0123456789ABCDEF")),
    ))(input);

    let (rest, (sign, prefix, num)) = match result {
        Ok(e) => e,
        Err(_) => {
            // If it wasn't a prefixed number, we attempt to parse it as a float
            let (rest, float) = context("float", recognize_float)(input)?;
            // Sign is none because it will be handled by parse<f64> below
            (rest, (None, "", float))
        }
    };

    // The above functions only match + and - characters for signs
    let sign_mult = match sign {
        None | Some('+') => 1,
        Some('-') => -1,
        Some(_) => unreachable!(),
    };

    // The above functions only match "0b", "0o", "0x", and "" strings for prefix
    let radix = match prefix {
        "0b" => 2,
        "0o" => 8,
        "" => 10,
        "0x" => 16,
        _ => unreachable!(),
    };

    // Parse the number to whatever's appropriate
    let numeric = if let Ok(int_val) = i32::from_str_radix(num, radix) {
        Numeric::Int(int_val * sign_mult)
    } else if let Ok(long_val) = i64::from_str_radix(num, radix) {
        Numeric::Long(long_val * sign_mult as i64)
    } else if let Ok(float_val) = num.parse::<f64>() {
        // Floats can only be base 10 so we use num.parse for more float features (exponents, decimals, etc)
        Numeric::Double(OrderedFloat::from(float_val * sign_mult as f64))
    } else {
        return IResult::Err(nom::Err::Error(VerboseError {
            errors: vec![(rest, VerboseErrorKind::Nom(ErrorKind::IsNot))],
        }));
    };

    IResult::Ok((rest, numeric))
}

/// Try to parse attribute value into a number
fn parse_attr_val_num(input: &str) -> Res<&str, Value> {
    context("attr value number", parse_ilf_number)(input)
        .map(|(rest, val)| (rest, Value::VNum(val)))
}

/// Attempts to parse an attribute value into a enum by just casting whatever characters are in it into a string
fn parse_attr_val_enum(input: &str) -> Res<&str, Value> {
    context("attr value enum", attr_token)(input)
        .map(|(rest, val)| (rest, Value::VString(val.to_string())))
}

/// Attempts to parse an attribute value into a string, obeying quote escape rules
fn parse_attr_val_string(input: &str) -> Res<&str, Value> {
    // Figure out if this string uses ' or " delimiters
    let (rest, delimiter) = alt((char('"'), char('\'')))(input)?;

    // Keep track of where we are in the string
    let mut remaining: &str = rest;
    let mut string = String::new();

    // Used for error reporting
    let mut last_escaped_quote_evidence: Option<&str> = None;
    loop {
        let (rest, c) = anychar(remaining)?;
        remaining = rest;

        match c {
            '\\' => {
                let (escaped_rest, escaped_char) = anychar(remaining)?;
                remaining = escaped_rest;
                match escaped_char {
                    '\\' => string.push(escaped_char),
                    // If the next character is the string delimiter (' or ") then it's just an escaped version
                    c if c == delimiter => {
                        last_escaped_quote_evidence = Some(rest);
                        string.push(escaped_char)
                    }
                    // Don't bother trying to un-escape other types of characters
                    // TODO: if we're matching JAVA's behavior, this should error
                    _ => {
                        string.push('\\');
                        string.push(escaped_char)
                    }
                };
            }
            c if c == delimiter => {
                // If the string is ending, make sure it wasn't tricked by a badly-escaped quote
                if check_for_end_of_value(rest).is_err() {
                    // If the character after a string ends isn't spaces followed by a semicolon or close paren,
                    //  something is wrong. Fail ILF parsing.

                    let mut errors = vec![(
                        rest,
                        VerboseErrorKind::Context(
                            "String Ending when it shouldn't. Check for badly-escaped quotes.",
                        ),
                    )];

                    // If we have evidence for a previous quote escape, add it to the context stack
                    if let Some(e) = last_escaped_quote_evidence {
                        errors.push((
                            e,
                            VerboseErrorKind::Context("potential badly escaped quote here"),
                        ))
                    }

                    return IResult::Err(nom::Err::Failure(VerboseError { errors }));
                }
                break;
            }
            // By default, just push to the string
            c => string.push(c),
        }
    }

    Ok((remaining, Value::VString(string)))
}

/// Attempts to parse ILF key=value pairs
fn parse_attr(input: &str) -> Res<&str, (&str, Value)> {
    tuple((
        context("key", parse_attr_key),
        context("value", parse_attr_val),
    ))(input)
}

// Attempts to parse the final "attributes" field of an IlF record
pub fn parse_attrs(input: &str) -> Res<&str, HashMap<String, Value>> {
    let (rest, attrs) = context(
        "Attributes",
        delimited(
            tuple((space0, char('('))),
            many0(parse_attr),
            tuple((space0, char(')'))),
        ),
    )(input)?;

    let attr_map = attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    Ok((rest, attr_map))
}
