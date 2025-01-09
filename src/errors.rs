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

use std::fmt::Display;

use nom::error::{VerboseError, VerboseErrorKind};
use thiserror::Error;

#[derive(Error)]
pub struct ILFParseError {
    pub parse_error: String,
    pub ilf: String,
}

impl Display for ILFParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.ilf.len() > 500 {
            let printable_ilf: String = self.ilf.chars().take(500).collect();
            write!(
                f,
                "Parse Error: {}\nILF: {:?}[...]",
                self.parse_error, printable_ilf
            )
        } else {
            write!(f, "Parse Error: {}\nILF: {:?}", self.parse_error, &self.ilf)
        }
    }
}

impl std::fmt::Debug for ILFParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Parse Error: {}\nILF: {}", self.parse_error, self.ilf)
    }
}

// == Error conversion code ==
// This is mostly copied from nom/src/error.rs/convert_error, with some slight adjustments.

pub trait Offset {
    /// offset between the first byte of self and the first byte of the argument
    fn offset(&self, second: &Self) -> usize;
}

impl<'a> Offset for &'a str {
    fn offset(&self, second: &Self) -> usize {
        let fst = self.as_ptr();
        let snd = second.as_ptr();

        snd as usize - fst as usize
    }
}

/// transforms a `VerboseError` into a trace with input position information. Trims line so output will be < 200 chars.
pub fn pretty_print_error(input: &str, e: VerboseError<&str>) -> String {
    use std::fmt::Write;

    let mut result = String::new();

    for (i, (substring, kind)) in e.errors.iter().enumerate() {
        let offset = input.find(substring);

        if input.is_empty() {
            match kind {
                VerboseErrorKind::Char(c) => {
                    write!(&mut result, "{}: expected '{}', got empty input\n\n", i, c)
                }
                VerboseErrorKind::Context(s) => {
                    write!(&mut result, "{}: in {}, got empty input\n\n", i, s)
                }
                VerboseErrorKind::Nom(e) => {
                    write!(&mut result, "{}: in {:?}, got empty input\n\n", i, e)
                }
            }
        } else {
            match offset {
                None => match kind {
                    VerboseErrorKind::Char(c) => {
                        write!(
                            &mut result,
                            "{}: expected '{}', remaining {}\n\n",
                            i, c, substring
                        )
                    }
                    VerboseErrorKind::Context(s) => {
                        write!(&mut result, "{}: in {}, remaining {}\n\n", i, s, substring)
                    }
                    VerboseErrorKind::Nom(e) => {
                        write!(
                            &mut result,
                            "{}: in {:?}, remaining {}\n\n",
                            i, e, substring
                        )
                    }
                },
                Some(offset) => {
                    let prefix = &input.as_bytes()[..offset];

                    // Count the number of newlines in the first `offset` bytes of input
                    let line_number = prefix.iter().filter(|&&b| b == b'\n').count() + 1;

                    // Find the line that includes the subslice:
                    // Find the *last* newline before the substring starts
                    let line_begin = prefix
                        .iter()
                        .rev()
                        .position(|&b| b == b'\n')
                        .map(|pos| offset - pos)
                        .unwrap_or(0);

                    // Find the full line after that newline
                    let mut line = input[line_begin..]
                        .lines()
                        .next()
                        .unwrap_or(&input[line_begin..])
                        .trim_end();

                    // The (1-indexed) column number is the offset of our substring into that line
                    let mut column_number = line.offset(substring) + 1;

                    // ILF-specific code starts here.
                    // We don't want to print the entire line, because it's sometimes far too long to be readable.
                    // The maximum amount of characters to leave on either side of the offset
                    let trim_amount = 50;

                    if column_number > trim_amount {
                        let trim_point = line
                            .char_indices()
                            .nth(column_number - trim_amount)
                            .expect("Trim point should be within string")
                            .0;
                        line = &line[line.char_indices().nth(trim_point).unwrap().0..];
                        column_number = trim_amount;
                    }
                    if line.len() > column_number + trim_amount {
                        let trim_point = line
                            .char_indices()
                            .nth(column_number + trim_amount)
                            .expect("Trim point should be within string")
                            .0;
                        line = &line[..trim_point];
                    }

                    match kind {
                        VerboseErrorKind::Char(c) => {
                            if let Some(actual) = substring.chars().next() {
                                write!(
                                    &mut result,
                                    "{i}: at line {line_number}, pos {column_number}:\n\
                       {line}\n\
                       {caret:>column$}\n\
                       expected '{expected}', found {actual}\n\n",
                                    i = i,
                                    line_number = line_number,
                                    line = line,
                                    caret = '^',
                                    column = column_number,
                                    expected = c,
                                    actual = actual,
                                )
                            } else {
                                write!(
                                    &mut result,
                                    "{i}: at line {line_number}, pos {column_number}:\n\
                       {line}\n\
                       {caret:>column$}\n\
                       expected '{expected}', got end of input\n\n",
                                    i = i,
                                    line_number = line_number,
                                    line = line,
                                    caret = '^',
                                    column = column_number,
                                    expected = c,
                                )
                            }
                        }
                        VerboseErrorKind::Context(s) => write!(
                            &mut result,
                            "{i}: at line {line_number}, pos {column_number}, in {context}:\n\
                     {line}\n\
                     {caret:>column$}\n\n",
                            i = i,
                            line_number = line_number,
                            context = s,
                            line = line,
                            caret = '^',
                            column = column_number,
                        ),
                        VerboseErrorKind::Nom(e) => write!(
                            &mut result,
                            "{i}: at line {line_number}, pos {column_number}, in {nom_err:?}:\n\
                     {line}\n\
                     {caret:>column$}\n\n",
                            i = i,
                            line_number = line_number,
                            nom_err = e,
                            line = line,
                            caret = '^',
                            column = column_number,
                        ),
                    }
                }
            }
        }
        // Because `write!` to a `String` is infallible, this `unwrap` is fine.
        .unwrap();
    }

    result
}
