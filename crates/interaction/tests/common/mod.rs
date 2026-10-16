//! Shared test helpers: contract file loading and a reader for the single-line TOML subset the contract tables use (T-31).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    dead_code,
    reason = "T-38"
)]

use std::path::PathBuf;

use serde_json::{Map, Value};

pub(crate) fn contract(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/interaction")
        .join(rel)
}

pub(crate) fn json(rel: &str) -> Value {
    let text = std::fs::read_to_string(contract(rel)).unwrap();
    serde_json::from_str(&text).unwrap()
}

pub(crate) fn vectors(rel: &str) -> Vec<Value> {
    match json(rel) {
        Value::Array(items) => items,
        other => panic!("{rel}: not an array: {other}"),
    }
}

pub(crate) fn toml(rel: &str) -> Value {
    parse_toml(&std::fs::read_to_string(contract(rel)).unwrap())
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            '\\' if quoted => escaped = !escaped,
            '"' if !escaped => quoted = !quoted,
            '#' if !quoted => return &line[..i],
            _ => escaped = false,
        }
        if c != '\\' {
            escaped = false;
        }
    }
    line
}

fn split_key(key: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in key.chars() {
        match c {
            '"' => quoted = !quoted,
            '.' if !quoted => parts.push(std::mem::take(&mut current).trim().to_owned()),
            _ => current.push(c),
        }
    }
    parts.push(current.trim().to_owned());
    parts
}

fn table_at<'a>(root: &'a mut Map<String, Value>, path: &[String]) -> &'a mut Map<String, Value> {
    let mut node = root;
    for part in path {
        let entry = node
            .entry(part.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        node = match entry {
            Value::Object(m) => m,
            Value::Array(items) => match items.last_mut() {
                Some(Value::Object(m)) => m,
                _ => panic!("array of tables expected at {part}"),
            },
            _ => panic!("table expected at {part}"),
        };
    }
    node
}

struct Reader<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
}

impl Reader<'_> {
    fn skip_ws(&mut self) {
        while self.chars.peek().is_some_and(|c| c.is_whitespace()) {
            self.chars.next();
        }
    }

    fn value(&mut self) -> Value {
        self.skip_ws();
        match self.chars.peek().copied() {
            Some('"') => {
                self.chars.next();
                let mut s = String::new();
                let mut escaped = false;
                for c in self.chars.by_ref() {
                    if escaped {
                        s.push(match c {
                            'n' => '\n',
                            't' => '\t',
                            other => other,
                        });
                        escaped = false;
                        continue;
                    }
                    match c {
                        '"' => break,
                        '\\' => escaped = true,
                        _ => s.push(c),
                    }
                }
                Value::String(s)
            }
            Some('[') => {
                self.chars.next();
                let mut items = Vec::new();
                loop {
                    self.skip_ws();
                    match self.chars.peek() {
                        Some(']') => {
                            self.chars.next();
                            break;
                        }
                        Some(',') => {
                            self.chars.next();
                        }
                        _ => items.push(self.value()),
                    }
                }
                Value::Array(items)
            }
            Some('{') => {
                self.chars.next();
                let mut map = Map::new();
                loop {
                    self.skip_ws();
                    match self.chars.peek() {
                        Some('}') => {
                            self.chars.next();
                            break;
                        }
                        Some(',') => {
                            self.chars.next();
                        }
                        _ => {
                            let mut key = String::new();
                            for c in self.chars.by_ref() {
                                if c == '=' {
                                    break;
                                }
                                key.push(c);
                            }
                            let v = self.value();
                            map.insert(key.trim().trim_matches('"').to_owned(), v);
                        }
                    }
                }
                Value::Object(map)
            }
            _ => {
                let mut raw = String::new();
                while let Some(c) = self.chars.peek().copied() {
                    if matches!(c, ',' | ']' | '}') {
                        break;
                    }
                    raw.push(c);
                    self.chars.next();
                }
                let raw = raw.trim();
                match raw {
                    "true" => Value::Bool(true),
                    "false" => Value::Bool(false),
                    _ => raw
                        .parse::<i64>()
                        .map(Value::from)
                        .or_else(|_| raw.parse::<f64>().map(Value::from))
                        .unwrap_or_else(|_| panic!("unsupported TOML value {raw}")),
                }
            }
        }
    }
}

pub(crate) fn parse_toml(text: &str) -> Value {
    let mut root = Map::new();
    let mut path: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]")) {
            path = split_key(header);
            let (last, parent) = path.split_last().unwrap();
            let table = table_at(&mut root, parent);
            let entry = table
                .entry(last.clone())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(items) = entry {
                items.push(Value::Object(Map::new()));
            }
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            path = split_key(header);
            table_at(&mut root, &path);
            continue;
        }
        let (key, value) = line.split_once('=').unwrap();
        let mut reader = Reader {
            chars: value.chars().peekable(),
        };
        let parsed = reader.value();
        let keys = split_key(key);
        let (last, parent) = keys.split_last().unwrap();
        let mut full = path.clone();
        full.extend(parent.iter().cloned());
        table_at(&mut root, &full).insert(last.clone(), parsed);
    }
    Value::Object(root)
}

pub(crate) fn subset(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => e
            .iter()
            .all(|(k, v)| a.get(k).is_some_and(|x| subset(v, x))),
        _ => expected == actual,
    }
}
