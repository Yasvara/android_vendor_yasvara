// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust zero-JS HTML5 semantic extractor for `Jelajah Fast`
//! (`SPEC-0051` §5.8): extracts page title, readable text blocks, clickable
//! links, and automatically classifies flashable firmware/ROM links
//! (`.zip`, `.img`, `.zst`, `.tar`, `.yvbak`).

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedLink {
    pub href: String,
    pub label: String,
    pub is_flashable: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedPage {
    pub title: String,
    pub links: Vec<ExtractedLink>,
    pub text_lines: Vec<String>,
}

/// Returns `true` if `url` looks like a downloadable firmware/OTA/backup artifact.
pub fn is_flashable_url(url: &str) -> bool {
    let base = url.split('?').next().unwrap_or(url).to_ascii_lowercase();
    base.ends_with(".zip")
        || base.ends_with(".img")
        || base.ends_with(".img.zst")
        || base.ends_with(".tar.zst")
        || base.ends_with(".yvbak")
}

/// Parse an HTML document into title, links, and readable text lines without panicking
/// on malformed markup or arbitrary UTF-8.
pub fn parse_html(input: &str) -> ParsedPage {
    let mut page = ParsedPage::default();
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut in_title = false;
    let mut in_script_or_style = false;
    let mut current_href: Option<String> = None;
    let mut current_link_label = String::new();
    let mut current_text = String::new();

    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some(rel_end) = input[i..].find('>') {
                let tag_raw = &input[i + 1..i + rel_end];
                let tag_trimmed = tag_raw.trim();
                let lower = tag_trimmed.to_ascii_lowercase();

                if lower.starts_with("script") || lower.starts_with("style") {
                    in_script_or_style = true;
                } else if lower.starts_with("/script") || lower.starts_with("/style") {
                    in_script_or_style = false;
                } else if lower.starts_with("title") {
                    in_title = true;
                } else if lower.starts_with("/title") {
                    in_title = false;
                } else if lower.starts_with("a ") || lower == "a" {
                    if let Some(href) = extract_attr(tag_trimmed, "href") {
                        current_href = Some(href);
                        current_link_label.clear();
                    }
                } else if lower.starts_with("/a") {
                    if let Some(href) = current_href.take() {
                        let label = current_link_label.trim().to_string();
                        let display = if label.is_empty() { href.clone() } else { label };
                        let is_flashable = is_flashable_url(&href);
                        page.links.push(ExtractedLink {
                            href,
                            label: display,
                            is_flashable,
                        });
                    }
                    current_link_label.clear();
                } else if lower.starts_with("p")
                    || lower.starts_with("/p")
                    || lower.starts_with("br")
                    || lower.starts_with("div")
                    || lower.starts_with("/div")
                    || lower.starts_with("li")
                    || lower.starts_with("h1")
                    || lower.starts_with("h2")
                    || lower.starts_with("h3")
                {
                    flush_line(&mut current_text, &mut page.text_lines);
                }

                i += rel_end + 1;
                continue;
            }
        }

        let next_tag = input[i..].find('<').map(|p| i + p).unwrap_or(bytes.len());
        let chunk = &input[i..next_tag];
        if !in_script_or_style {
            let decoded = decode_entities(chunk);
            if in_title {
                page.title.push_str(&decoded);
            } else {
                if current_href.is_some() {
                    current_link_label.push_str(&decoded);
                }
                current_text.push_str(&decoded);
            }
        }
        i = next_tag;
    }

    flush_line(&mut current_text, &mut page.text_lines);
    page.title = page.title.trim().to_string();
    page
}

fn flush_line(buf: &mut String, out: &mut Vec<String>) {
    let trimmed = buf.split_whitespace().collect::<Vec<_>>().join(" ");
    if !trimmed.is_empty() {
        out.push(trimmed);
    }
    buf.clear();
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{attr}=");
    let pos = lower.find(&needle)?;
    let rest = tag[pos + needle.len()..].trim_start();
    if let Some(q) = rest.chars().next() {
        if q == '"' || q == '\'' {
            let inner = &rest[1..];
            let end = inner.find(q)?;
            return Some(decode_entities(&inner[..end]));
        }
    }
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(decode_entities(&rest[..end]))
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_title_links_and_flashable_ota_zips() {
        let html = r#"
        <html><head><title>Yasvara Releases</title><script>alert(1)</script></head>
        <body>
          <h1>Yasvara 1.0 for onyx</h1>
          <p><a href="https://github.com/Yasvara/releases/Yasvara-1.0-onyx.zip?dl=1">Download OTA ZIP</a></p>
          <p><a href="https://github.com/Yasvara/releases/boot.img">Boot Image</a></p>
          <p><a href="https://yasvara.org/changelog">Changelog &amp; Notes</a></p>
        </body></html>"#;
        let page = parse_html(html);
        assert_eq!(page.title, "Yasvara Releases");
        assert_eq!(page.links.len(), 3);
        assert!(page.links[0].is_flashable);
        assert!(page.links[1].is_flashable);
        assert!(!page.links[2].is_flashable);
        assert_eq!(page.links[2].label, "Changelog & Notes");
        assert!(!page.text_lines.iter().any(|l| l.contains("alert")));
    }
}
