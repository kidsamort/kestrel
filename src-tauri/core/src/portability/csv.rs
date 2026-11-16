//! RFC 4180 CSV import and export.

use super::common::{build_item, category_from, field, utf8};
use super::{ImportFailure, Parsed, ParsedItem};
use crate::model::Item;
use crate::session::VaultError;

/// CSV columns the importer understands and the exporter writes, in order.
const CSV_COLUMNS: [&str; 7] = [
    "title", "category", "username", "password", "url", "notes", "tags",
];

struct CsvRecord {
    fields: Vec<String>,
    error: Option<String>,
}

/// Where scanning one field stopped.
enum Step {
    /// The field ended at a comma; the record continues.
    EndField,
    /// The field ended at a newline (or at end of input after a closing quote).
    EndRecord,
    /// Malformed input; the rest of the line was skipped.
    Failed(&'static str),
    /// End of input inside an unquoted field.
    EndOfInput,
}

pub(super) fn parse_csv(bytes: &[u8]) -> Result<Parsed, VaultError> {
    let mut records = split_csv(utf8(bytes, "CSV")?);
    if records.is_empty() {
        return Err(VaultError::Invalid("the CSV file is empty".into()));
    }
    let header = records.remove(0);
    if let Some(error) = header.error {
        return Err(VaultError::Invalid(format!(
            "the CSV header row could not be parsed: {error}"
        )));
    }

    let mut columns: [Option<usize>; CSV_COLUMNS.len()] = [None; CSV_COLUMNS.len()];
    for (index, cell) in header.fields.iter().enumerate() {
        let name = cell.trim().to_ascii_lowercase();
        if let Some(position) = CSV_COLUMNS.iter().position(|column| *column == name) {
            if columns[position].is_none() {
                columns[position] = Some(index);
            }
        }
    }
    if columns[0].is_none() {
        return Err(VaultError::Invalid(
            "the CSV header needs a `title` column (recognised columns: title, category, \
             username, password, url, notes, tags)"
                .into(),
        ));
    }

    let mut parsed = Parsed::default();
    for (offset, record) in records.into_iter().enumerate() {
        // The header is row 1, so the first data record is row 2.
        let row_number = offset + 2;
        if let Some(reason) = record.error {
            parsed.failed.push(ImportFailure {
                row: row_number,
                reason,
            });
            continue;
        }
        if record.fields.iter().all(|field| field.trim().is_empty()) {
            parsed.skipped += 1;
            continue;
        }
        parsed.items.push(ParsedItem {
            row: row_number,
            item: csv_record_to_item(&record.fields, &columns),
        });
    }
    Ok(parsed)
}

fn csv_record_to_item(row: &[String], columns: &[Option<usize>; CSV_COLUMNS.len()]) -> Item {
    let cell = |position: usize| {
        columns[position]
            .and_then(|index| row.get(index))
            .map(|value| value.trim())
            .unwrap_or("")
    };
    let category = category_from(cell(1));
    let username = cell(2);
    let password = cell(3);
    let url = cell(4);
    let tags = cell(6)
        .split(';')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect();

    let mut fields = Vec::new();
    if !username.is_empty() {
        fields.push(field("username", "username", username, false));
    }
    if !password.is_empty() {
        fields.push(field("password", "password", password, true));
    }
    let urls = if url.is_empty() {
        Vec::new()
    } else {
        vec![url.to_string()]
    };

    build_item(
        cell(0).to_string(),
        category,
        fields,
        cell(5).to_string(),
        urls,
        tags,
        false,
        None,
        None,
    )
}

/// Split RFC 4180-style CSV into records.
///
/// Inside a quoted field, `""` is a literal quote and any character — comma and
/// newline included — is data. A malformed record is returned with an error and
/// the parser resynchronises on the next newline, so one bad row never hides
/// the rest of the file.
fn split_csv(text: &str) -> Vec<CsvRecord> {
    let chars: Vec<char> = text.chars().collect();
    let mut records = Vec::new();
    let mut fields: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut index = usize::from(chars.first() == Some(&'\u{feff}'));

    loop {
        // Carriage returns before a field carry no data; the ones inside a
        // field are skipped by the field scanner.
        while chars.get(index) == Some(&'\r') {
            index += 1;
        }
        let Some(&ch) = chars.get(index) else {
            break;
        };
        let step = if ch == '"' {
            consume_quoted(&chars, &mut index, &mut field, &mut fields)
        } else {
            consume_unquoted(&chars, &mut index, &mut field, &mut fields)
        };
        match step {
            Step::EndField => {}
            Step::EndRecord => finish_record(&mut records, &mut fields),
            Step::Failed(reason) => {
                records.push(CsvRecord {
                    fields: Vec::new(),
                    error: Some(reason.to_string()),
                });
                fields.clear();
                field.clear();
            }
            Step::EndOfInput => break,
        }
    }
    // A file may end without a newline; that partial row is still a row if
    // anything was read.
    if !field.is_empty() || !fields.is_empty() {
        fields.push(std::mem::take(&mut field));
        finish_record(&mut records, &mut fields);
    }
    records
}

/// Consume one quoted field, starting at its opening quote. The closing quote
/// and the delimiter after it are consumed too, so the caller only has to look
/// at the returned [`Step`].
fn consume_quoted(
    chars: &[char],
    index: &mut usize,
    field: &mut String,
    fields: &mut Vec<String>,
) -> Step {
    *index += 1;
    loop {
        let Some(&ch) = chars.get(*index) else {
            return Step::Failed("unterminated quoted field");
        };
        if ch != '"' {
            field.push(ch);
            *index += 1;
            continue;
        }
        if chars.get(*index + 1) == Some(&'"') {
            field.push('"');
            *index += 2;
            continue;
        }
        *index += 1;
        break;
    }
    loop {
        match chars.get(*index).copied() {
            None => {
                fields.push(std::mem::take(field));
                return Step::EndRecord;
            }
            Some(',') => {
                fields.push(std::mem::take(field));
                *index += 1;
                return Step::EndField;
            }
            Some('\r') => *index += 1,
            Some('\n') => {
                fields.push(std::mem::take(field));
                *index += 1;
                return Step::EndRecord;
            }
            Some(_) => {
                skip_to_newline(chars, index);
                return Step::Failed("unexpected characters after a closing quote");
            }
        }
    }
}

/// Consume one unquoted field, starting at its first character.
fn consume_unquoted(
    chars: &[char],
    index: &mut usize,
    field: &mut String,
    fields: &mut Vec<String>,
) -> Step {
    while let Some(&ch) = chars.get(*index) {
        match ch {
            '"' => {
                skip_to_newline(chars, index);
                return Step::Failed("a quote inside an unquoted field");
            }
            ',' => {
                fields.push(std::mem::take(field));
                *index += 1;
                return Step::EndField;
            }
            '\r' => *index += 1,
            '\n' => {
                fields.push(std::mem::take(field));
                *index += 1;
                return Step::EndRecord;
            }
            _ => {
                field.push(ch);
                *index += 1;
            }
        }
    }
    Step::EndOfInput
}

fn finish_record(records: &mut Vec<CsvRecord>, fields: &mut Vec<String>) {
    records.push(CsvRecord {
        fields: std::mem::take(fields),
        error: None,
    });
}

fn skip_to_newline(chars: &[char], index: &mut usize) {
    while *index < chars.len() && chars[*index] != '\n' {
        *index += 1;
    }
    if *index < chars.len() {
        *index += 1;
    }
}

pub(super) fn export_csv(items: &[Item]) -> String {
    let mut out = String::new();
    out.push_str(&CSV_COLUMNS.join(","));
    out.push('\n');
    for item in items {
        let username = item
            .fields
            .iter()
            .find(|field| field.kind == "username")
            .map(|field| field.value.as_str())
            .unwrap_or("");
        let password = item
            .fields
            .iter()
            .find(|field| field.kind == "password")
            .map(|field| field.value.as_str())
            .unwrap_or("");
        let url = item
            .urls
            .first()
            .map(String::as_str)
            .or_else(|| {
                item.fields
                    .iter()
                    .find(|field| field.kind == "url")
                    .map(|field| field.value.as_str())
            })
            .unwrap_or("");
        let row = [
            item.title.as_str(),
            item.category.as_str(),
            username,
            password,
            url,
            item.notes.as_str(),
            &item.tags.join(";"),
        ];
        let cells: Vec<String> = row.iter().map(|cell| csv_escape(cell)).collect();
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
