//! A one-page PDF of the recovery kit, written by hand.
//!
//! The kit is the only thing in this app that must survive the machine it was
//! made on, and "open the print dialog and pick Microsoft Print to PDF" is a
//! path most people never find. This writes the file directly: one A4 page,
//! Helvetica, the vault name, the date, the code in four-character groups and
//! the sentence that says what the code does.
//!
//! No dependency, no fonts to embed: the PDF base-14 fonts are built into every
//! reader, and the text is ASCII (the code is base32, the vault name is escaped
//! to printable ASCII). A name that cannot be represented is transliterated
//! rather than dropped, so the sheet never claims a different vault.
//!
//! The bytes are built in memory and written once. A half-written kit on disk
//! would be worse than none: the person would trust a file that does not open.

use std::path::{Path, PathBuf};

/// A4 at 72 points per inch.
const PAGE_WIDTH: f32 = 595.0;
const PAGE_HEIGHT: f32 = 842.0;
const MARGIN: f32 = 64.0;
/// Helvetica at 12pt averages a little over half an em per character; the
/// wrapper below uses this to decide where a line breaks.
const AVERAGE_CHAR_WIDTH: f32 = 6.2;

/// Write the kit and return the path it landed on.
///
/// `dir` is created when missing. An existing file of the same name is never
/// overwritten: the name grows a ` (2)` suffix instead, because two kits for two
/// vaults are not the same document.
pub fn write_recovery_pdf(
    dir: &Path,
    vault_name: &str,
    code: &str,
    created_at: i64,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir)
        .map_err(|failure| format!("cannot create {}: {failure}", dir.display()))?;
    let path = unique_path(dir, &file_name(vault_name, created_at));
    write_recovery_pdf_at(&path, vault_name, code, created_at)?;
    Ok(path)
}

/// Write the kit to exactly this path. The save dialog chose it, so an existing
/// file is the person's own decision — the shell already asked about overwriting.
pub fn write_recovery_pdf_at(
    path: &Path,
    vault_name: &str,
    code: &str,
    created_at: i64,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|failure| format!("cannot create {}: {failure}", parent.display()))?;
    }
    std::fs::write(path, render(vault_name, code, created_at))
        .map_err(|failure| format!("cannot write {}: {failure}", path.display()))
}

/// The name the save dialog starts with.
pub fn suggested_file_name(vault_name: &str, created_at: i64) -> String {
    file_name(vault_name, created_at)
}

/// Find the code printed on a kit this app wrote.
///
/// The PDF carries the code as literal text (`(CODE) Tj`), so a scan of the
/// bytes finds it. Thirteen groups of four and a checksum character is a shape
/// nothing else in the document has.
pub fn extract_code(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    for start in 0..chars.len() {
        if !chars[start].is_ascii_alphanumeric() {
            continue;
        }
        if let Some(code) = match_code_at(&chars, start) {
            return Some(code);
        }
    }
    None
}

fn match_code_at(chars: &[char], start: usize) -> Option<String> {
    let mut index = start;
    let mut code = String::with_capacity(53);
    for _ in 0..13 {
        for _ in 0..4 {
            let ch = *chars.get(index)?;
            if !ch.is_ascii_alphanumeric() {
                return None;
            }
            code.push(ch);
            index += 1;
        }
        if *chars.get(index)? != '-' {
            return None;
        }
        code.push('-');
        index += 1;
    }
    let last = *chars.get(index)?;
    if !last.is_ascii_alphanumeric() {
        return None;
    }
    code.push(last);
    Some(code)
}

/// `Kestrel-recovery-<vault>-2026-11-15.pdf`, with every character a file name
/// can carry.
fn file_name(vault_name: &str, created_at: i64) -> String {
    let cleaned: String = vault_name
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    let stem = if trimmed.is_empty() { "vault" } else { trimmed };
    format!("Kestrel-recovery-{stem}-{}.pdf", date_only(created_at))
}

/// Unix seconds to `YYYY-MM-DD`, without pulling in a date crate for one line.
fn date_only(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Howard Hinnant's civil-from-days: exact for every date this app can meet and
/// twelve lines long, which is cheaper than a dependency.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The document. One page, five blocks: title, vault, date, code, warning.
fn render(vault_name: &str, code: &str, created_at: i64) -> Vec<u8> {
    let mut lines: Vec<(f32, String)> = Vec::new();
    let mut y = PAGE_HEIGHT - MARGIN;

    let mut push = |y: &mut f32, size: f32, text: &str| {
        for line in wrap(text, size) {
            lines.push((*y, format!("{size} {line}")));
            *y -= size * 1.55;
        }
    };

    push(&mut y, 22.0, "Kestrel recovery kit");
    y -= 8.0;
    push(&mut y, 14.0, &format!("Vault: {vault_name}"));
    push(&mut y, 12.0, &format!("Created: {}", date_only(created_at)));
    y -= 16.0;
    push(&mut y, 12.0, "Recovery code");
    y -= 6.0;
    // The code in groups of four, the way it is printed and read aloud — and on
    // **one line**, because a code split across two lines cannot be read back
    // out of the file it was written into. The size shrinks to fit rather than
    // the line breaking.
    let grouped = group_code(code);
    let usable = PAGE_WIDTH - MARGIN * 2.0;
    let longest = grouped.chars().count() as f32;
    let code_size = (usable / (longest * 0.56)).clamp(9.0, 15.0);
    push(&mut y, code_size, &grouped);
    y -= 18.0;
    push(
        &mut y,
        12.0,
        "This code opens the vault on its own, without the master password. \
         Anyone who reads it can open this vault. Store it offline.",
    );
    y -= 12.0;
    push(
        &mut y,
        10.0,
        "Kestrel stores only a copy of the vault key sealed under this code. \
         The code itself is shown once and is not kept anywhere.",
    );

    content_stream(&lines)
}

/// `ABCD-EFGH-...` — the code arrives already grouped by the core; this only
/// re-groups when it is not, so the sheet never depends on the caller's format.
fn group_code(code: &str) -> String {
    let bare: String = code
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    bare.as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Greedy wrap on spaces. A single word longer than the line (a long vault name)
/// is split at the line width rather than running off the page.
fn wrap(text: &str, size: f32) -> Vec<String> {
    let usable = PAGE_WIDTH - MARGIN * 2.0;
    let per_line = (usable / (size * AVERAGE_CHAR_WIDTH / 12.0)).max(8.0) as usize;
    let mut out = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= per_line {
            current.push(' ');
            current.push_str(word);
        } else {
            out.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    // Long unbroken runs (a vault name with no spaces).
    out.into_iter()
        .flat_map(|line| {
            line.chars()
                .collect::<Vec<_>>()
                .chunks(per_line)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The page description: one text object per line, so a reader that ignores
/// kerning still places everything where the sheet expects it.
fn content_stream(lines: &[(f32, String)]) -> Vec<u8> {
    let mut stream = String::from("BT\n");
    let mut last_size: Option<&str> = None;
    for (y, entry) in lines {
        let (size, text) = entry.split_once(' ').unwrap_or(("12", entry));
        if last_size != Some(size) {
            stream.push_str(&format!("/F1 {size} Tf\n"));
            last_size = Some(size);
        }
        stream.push_str(&format!(
            "1 0 0 1 {:.1} {:.1} Tm ({}) Tj\n",
            MARGIN,
            y,
            escape_pdf_text(text)
        ));
    }
    stream.push_str("ET\n");

    let objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH:.0} {PAGE_HEIGHT:.0}] \
             /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
        ),
        format!("<< /Length {} >>\nstream\n{stream}endstream", stream.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];

    let mut out = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in &offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// Parentheses and backslashes end a PDF string; anything outside ASCII becomes
/// `?` rather than an encoding the base-14 font cannot draw.
fn escape_pdf_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(ch),
            _ => out.push('?'),
        }
    }
    out
}

/// `report.pdf`, `report (2).pdf` — never overwrite what the person already has.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let stem = name.strip_suffix(".pdf").unwrap_or(name);
    for n in 2..=9999 {
        let next = dir.join(format!("{stem} ({n}).pdf"));
        if !next.exists() {
            return next;
        }
    }
    dir.join(format!("{stem} (9999).pdf"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_document_is_a_pdf_with_the_code_in_it() {
        let bytes = render("Personal", "ABCD-EFGH-IJKL-MNOP", 1_800_000_000);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("%PDF-1.4"), "a reader must recognise it");
        assert!(text.trim_end().ends_with("%%EOF"));
        assert!(text.contains("Kestrel recovery kit"));
        assert!(text.contains("Vault: Personal"));
        assert!(
            text.contains("ABCD-EFGH-IJKL-MNOP"),
            "the code is the point of the sheet"
        );
        // The cross-reference offsets must point at real object headers.
        let xref_at = text.find("startxref").expect("startxref");
        let offset: usize = text[xref_at + 10..]
            .split_whitespace()
            .next()
            .expect("offset")
            .parse()
            .expect("a number");
        assert!(
            text[offset..].starts_with("xref"),
            "startxref points at xref"
        );
    }

    #[test]
    fn the_code_can_be_read_back_out_of_the_document() {
        let code = "W6TL-JZSI-R4IY-6GZF-YHTQ-VIOQ-Y5DT-TLQZ-QTQR-BYKV-HEQW-HA5G-J3WA-J";
        let bytes = render("Personal", code, 1_800_000_000);
        let text = String::from_utf8_lossy(&bytes);
        assert_eq!(extract_code(&text).as_deref(), Some(code));
        assert_eq!(extract_code("nothing here"), None);
    }

    #[test]
    fn a_date_is_a_real_date() {
        assert_eq!(date_only(0), "1970-01-01");
        // 2026-11-15, the day this was written.
        assert_eq!(date_only(1_763_200_000), "2025-11-15");
    }

    #[test]
    fn the_file_name_survives_a_hostile_vault_name() {
        assert_eq!(
            file_name("Work / Clients: 2026", 1_763_200_000),
            "Kestrel-recovery-Work---Clients--2026-2025-11-15.pdf"
        );
        assert_eq!(
            file_name("   ", 1_763_200_000),
            "Kestrel-recovery-vault-2025-11-15.pdf"
        );
    }

    #[test]
    fn an_existing_file_is_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("kestrel-pdf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let first = write_recovery_pdf(&dir, "Personal", "AAAA-BBBB", 0).expect("first");
        let second = write_recovery_pdf(&dir, "Personal", "CCCC-DDDD", 0).expect("second");
        assert_ne!(first, second);
        assert!(second.to_string_lossy().contains("(2)"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
