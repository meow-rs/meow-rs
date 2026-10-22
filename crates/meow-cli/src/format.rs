//! Text output helpers.

/// Rows whose leading columns are padded to a common width. The last
/// column is a name, which may hold CJK or emoji whose terminal width
/// differs from their length, so it is never padded and cannot break the
/// alignment of the columns before it.
pub struct Table {
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(header: &[&str]) -> Self {
        Self {
            rows: vec![header.iter().map(ToString::to_string).collect()],
        }
    }

    pub fn row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    pub fn is_empty(&self) -> bool {
        self.rows.len() <= 1
    }

    pub fn render(&self) -> String {
        let columns = self.rows.iter().map(Vec::len).max().unwrap_or(0);
        let mut widths = vec![0; columns.saturating_sub(1)];
        for row in &self.rows {
            for (width, cell) in widths.iter_mut().zip(row) {
                *width = (*width).max(cell.chars().count());
            }
        }
        let mut text = String::new();
        for row in &self.rows {
            let mut line = String::new();
            for (index, cell) in row.iter().enumerate() {
                if index > 0 {
                    line.push_str("  ");
                }
                line.push_str(cell);
                if let Some(&width) = widths.get(index) {
                    let used = cell.chars().count();
                    line.extend(std::iter::repeat_n(' ', width.saturating_sub(used)));
                }
            }
            text.push_str(line.trim_end());
            text.push('\n');
        }
        text
    }
}

/// `1536` as `1.5 KB`, in binary units as dashboards show them.
pub fn bytes(count: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if count < 1024 {
        return format!("{count} B");
    }
    let mut value = count as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// An RFC 3339 time as `2026-10-22 08:30:01Z`: whole seconds, keeping the
/// offset meow wrote.
pub fn time(rfc3339: &str) -> String {
    let text = rfc3339.replacen('T', " ", 1);
    let Some(dot) = text.find('.') else {
        return text;
    };
    let offset = text[dot + 1..].trim_start_matches(|c: char| c.is_ascii_digit());
    format!("{}{offset}", &text[..dot])
}

/// Unix seconds as `2026-10-22 08:30:01Z`.
pub fn unix_time(seconds: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|moment| moment.format(&Rfc3339).ok())
        .map_or_else(|| seconds.to_string(), |text| time(&text))
}

/// A case-insensitive substring test for `--filter`.
pub fn matches(filter: Option<&str>, fields: &[&str]) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let filter = filter.to_lowercase();
    fields
        .iter()
        .any(|field| field.to_lowercase().contains(&filter))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_column_is_never_padded() {
        let mut table = Table::new(&["TYPE", "NAME"]);
        table.row(vec!["Selector".into(), "节点选择".into()]);
        table.row(vec!["URLTest".into(), "Auto".into()]);
        assert_eq!(
            table.render(),
            "TYPE      NAME\nSelector  节点选择\nURLTest   Auto\n"
        );
    }

    #[test]
    fn sizes_and_times_read_short() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(5 * 1024 * 1024 * 1024), "5.0 GB");
        assert_eq!(time("2026-10-22T08:30:01.123Z"), "2026-10-22 08:30:01Z");
        assert_eq!(
            time("2026-10-22T08:30:01+08:00"),
            "2026-10-22 08:30:01+08:00"
        );
        assert_eq!(unix_time(1_761_121_801), "2025-10-22 08:30:01Z");
    }
}
