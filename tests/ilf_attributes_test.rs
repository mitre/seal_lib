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

use ordered_float::OrderedFloat;
use seal_lib::{parse_ilf_number, pretty_print_error, Log, Numeric, Value};
#[test]
fn test_number_parsing() {
    let nums = vec![
        (
            "+1231e10",
            Some(Numeric::Double(OrderedFloat(12310000000000.0))),
        ),
        (
            "+1231E10",
            Some(Numeric::Double(OrderedFloat(12310000000000.0))),
        ),
        (
            "+1231.01e10",
            Some(Numeric::Double(OrderedFloat(12310100000000.0))),
        ),
        (".1", Some(Numeric::Double(OrderedFloat(0.1)))),
        ("+0x1231.01e10", None),
        ("+0b1231.01e10", None),
        ("+0x.1", None),
        ("+0xDEAD", Some(Numeric::Int(57005))),
        ("+0b110", Some(Numeric::Int(6))),
        ("+0o17", Some(Numeric::Int(15))),
        (
            "+0b10000000000000000000000000000000000000",
            Some(Numeric::Long(137438953472)),
        ),
        ("+3.11", Some(Numeric::Double(OrderedFloat(3.11)))),
        ("3.11", Some(Numeric::Double(OrderedFloat(3.11)))),
        ("-3.11", Some(Numeric::Double(OrderedFloat(-3.11)))),
        ("0", Some(Numeric::Int(0))),
        ("0.0", Some(Numeric::Double(OrderedFloat(0.0)))),
        ("1.", Some(Numeric::Double(OrderedFloat(1.0)))),
        (".789", Some(Numeric::Double(OrderedFloat(0.789)))),
        ("-.5", Some(Numeric::Double(OrderedFloat(-0.5)))),
        ("1e7", Some(Numeric::Double(OrderedFloat(10000000.0)))),
        ("1.e4", Some(Numeric::Double(OrderedFloat(10000.0)))),
        ("1.2e4", Some(Numeric::Double(OrderedFloat(12000.0)))),
        ("12.34", Some(Numeric::Double(OrderedFloat(12.34)))),
        ("-1E-7", Some(Numeric::Double(OrderedFloat(-0.0000001)))),
        (".3e-2", Some(Numeric::Double(OrderedFloat(0.003)))),
        (
            "-1.234E-12",
            Some(Numeric::Double(OrderedFloat(-1.234E-12))),
        ),
        (
            "-1.234e-12",
            Some(Numeric::Double(OrderedFloat(-1.234e-12))),
        ),
        ("1234zebra", None),
    ];

    for (num, expected_num) in nums {
        let input_num = num.to_string() + ";";
        match parse_ilf_number(input_num.as_str()) {
            Ok((_rest, result)) => match expected_num {
                Some(expected) => assert_eq!(result, expected, "{} failed to parse correctly", num),
                None => panic!("{} Should have failed to parse, got {}", num, result),
            },
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
                if let Some(n) = expected_num {
                    println!("{}", pretty_print_error(input_num.as_str(), e));
                    panic!("{} failed to parse. Expected {}", num, n)
                }
            }
            Err(e) => println!("other error: {:?}", e),
        };
    }
}

#[test]
fn test_from_tuple() {
    let log: Log = ("my_test_ilf", &[("attr", "attrval"), ("attr2", "2")][..]).into();

    assert_eq!(log.log_type, "my_test_ilf".to_string());
    assert_eq!(
        *log.attributes.get("attr").unwrap(),
        Value::VString("attrval".into())
    );
    assert_eq!(
        *log.attributes.get("attr2").unwrap(),
        Value::VString("2".into())
    );
}
