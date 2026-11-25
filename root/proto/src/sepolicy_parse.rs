// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust parser for Magisk / KernelSU `sepolicy.rule` files.
//!
//! Parses all standard runtime policy statements (`allow`, `deny`, `auditallow`, `dontaudit`,
//! `allowxperm`, `permissive`, `enforce`, `type`, `typeattribute`, `attribute`,
//! `type_transition`, `name_transition`, `type_change`, `type_member`, `genfscon`),
//! expanding `{ a b c }` brace groups into flat normalized rules ready for patching or CIL export.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvKind {
    Allow,
    Deny,
    AuditAllow,
    DontAudit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SepolicyStmt {
    Av {
        kind: AvKind,
        source: String,
        target: String,
        class: String,
        perm: String,
    },
    AvXperm {
        kind: AvKind,
        source: String,
        target: String,
        class: String,
        operation: String,
        perm_set: String,
    },
    Permissive {
        domain: String,
        permissive: bool,
    },
    CreateType {
        name: String,
        attributes: Vec<String>,
    },
    TypeAttribute {
        name: String,
        attributes: Vec<String>,
    },
    CreateAttribute {
        name: String,
    },
    TypeTransition {
        source: String,
        target: String,
        class: String,
        default_type: String,
        object_name: Option<String>,
    },
    TypeChange {
        source: String,
        target: String,
        class: String,
        default_type: String,
        is_member: bool,
    },
    Genfscon {
        fs_name: String,
        partial_path: String,
        context: String,
    },
}

/// Tokenizes a single `sepolicy.rule` line preserving `{ a b c }` groups as single tokens.
fn tokenize_line(line: &str) -> Result<Vec<String>, &'static str> {
    let mut tokens = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b'#' {
            break;
        }
        if bytes[i] == b'{' {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i] != b'}' {
                i += 1;
            }
            if i >= bytes.len() {
                return Err("unclosed brace group in sepolicy.rule");
            }
            i += 1;
            tokens.push(line[start..i].to_string());
        } else if bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            if i >= bytes.len() {
                return Err("unclosed quote in sepolicy.rule");
            }
            tokens.push(line[start..i].to_string());
            i += 1;
        } else {
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'#' {
                i += 1;
            }
            let tok = line[start..i].trim_end_matches(';');
            if !tok.is_empty() {
                tokens.push(tok.to_string());
            }
        }
    }
    Ok(tokens)
}

fn expand_set(tok: &str) -> Vec<String> {
    let trimmed = tok.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        trimmed[1..trimmed.len() - 1]
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    } else {
        vec![trimmed.to_string()]
    }
}

fn valid_ident(s: &str) -> bool {
    if s == "*" {
        return true;
    }
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Parses a complete `sepolicy.rule` document into normalized statements.
/// Invalid lines are skipped with diagnostics returned alongside valid statements so one
/// malformed line in a third-party module does not break all other rules.
pub fn parse_rules(text: &str) -> (Vec<SepolicyStmt>, Vec<String>) {
    let mut stmts = Vec::new();
    let mut errors = Vec::new();

    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens = match tokenize_line(line) {
            Ok(t) => t,
            Err(e) => {
                errors.push(format!("line {}: {e}", line_no + 1));
                continue;
            }
        };
        if tokens.is_empty() {
            continue;
        }
        match tokens[0].as_str() {
            "allow" | "deny" | "auditallow" | "dontaudit" => {
                let kind = match tokens[0].as_str() {
                    "allow" => AvKind::Allow,
                    "deny" => AvKind::Deny,
                    "auditallow" => AvKind::AuditAllow,
                    _ => AvKind::DontAudit,
                };
                if tokens.len() < 5 {
                    errors.push(format!("line {}: expected 5 tokens for {}", line_no + 1, tokens[0]));
                    continue;
                }
                for s in expand_set(&tokens[1]) {
                    for t in expand_set(&tokens[2]) {
                        for c in expand_set(&tokens[3]) {
                            for p in expand_set(&tokens[4]) {
                                if valid_ident(&s) && valid_ident(&t) && valid_ident(&c) && valid_ident(&p) {
                                    stmts.push(SepolicyStmt::Av {
                                        kind,
                                        source: s.clone(),
                                        target: t.clone(),
                                        class: c.clone(),
                                        perm: p,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            "allowxperm" | "auditallowxperm" | "dontauditxperm" => {
                if tokens.len() < 6 {
                    errors.push(format!("line {}: expected 6 tokens for {}", line_no + 1, tokens[0]));
                    continue;
                }
                let kind = match tokens[0].as_str() {
                    "allowxperm" => AvKind::Allow,
                    "auditallowxperm" => AvKind::AuditAllow,
                    _ => AvKind::DontAudit,
                };
                for s in expand_set(&tokens[1]) {
                    for t in expand_set(&tokens[2]) {
                        for c in expand_set(&tokens[3]) {
                            stmts.push(SepolicyStmt::AvXperm {
                                kind,
                                source: s.clone(),
                                target: t.clone(),
                                class: c.clone(),
                                operation: tokens[4].clone(),
                                perm_set: tokens[5].clone(),
                            });
                        }
                    }
                }
            }
            "permissive" | "enforce" => {
                if tokens.len() < 2 {
                    errors.push(format!("line {}: missing domain", line_no + 1));
                    continue;
                }
                let permissive = tokens[0] == "permissive";
                for d in expand_set(&tokens[1]) {
                    if valid_ident(&d) {
                        stmts.push(SepolicyStmt::Permissive { domain: d, permissive });
                    }
                }
            }
            "create" | "type" => {
                if tokens.len() < 2 {
                    continue;
                }
                let attrs = if tokens.len() >= 3 { expand_set(&tokens[2]) } else { Vec::new() };
                for name in expand_set(&tokens[1]) {
                    if valid_ident(&name) {
                        stmts.push(SepolicyStmt::CreateType { name, attributes: attrs.clone() });
                    }
                }
            }
            "attradd" | "typeattribute" => {
                if tokens.len() < 3 {
                    continue;
                }
                let attrs = expand_set(&tokens[2]);
                for name in expand_set(&tokens[1]) {
                    if valid_ident(&name) {
                        stmts.push(SepolicyStmt::TypeAttribute { name, attributes: attrs.clone() });
                    }
                }
            }
            "attribute" => {
                if tokens.len() < 2 {
                    continue;
                }
                for name in expand_set(&tokens[1]) {
                    if valid_ident(&name) {
                        stmts.push(SepolicyStmt::CreateAttribute { name });
                    }
                }
            }
            "type_transition" | "name_transition" => {
                if tokens.len() < 5 {
                    continue;
                }
                let obj = tokens.get(5).cloned();
                stmts.push(SepolicyStmt::TypeTransition {
                    source: tokens[1].clone(),
                    target: tokens[2].clone(),
                    class: tokens[3].clone(),
                    default_type: tokens[4].clone(),
                    object_name: obj,
                });
            }
            "type_change" | "type_member" => {
                if tokens.len() < 5 {
                    continue;
                }
                stmts.push(SepolicyStmt::TypeChange {
                    source: tokens[1].clone(),
                    target: tokens[2].clone(),
                    class: tokens[3].clone(),
                    default_type: tokens[4].clone(),
                    is_member: tokens[0] == "type_member",
                });
            }
            "genfscon" => {
                if tokens.len() < 4 {
                    continue;
                }
                stmts.push(SepolicyStmt::Genfscon {
                    fs_name: tokens[1].clone(),
                    partial_path: tokens[2].clone(),
                    context: tokens[3].clone(),
                });
            }
            other => {
                errors.push(format!("line {}: unknown statement '{other}'", line_no + 1));
            }
        }
    }
    (stmts, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sets_transitions_permissive_and_genfscon() {
        let doc = r#"
            # Sample module sepolicy.rule
            allow { init su } { system_file vendor_file } file { read open }
            permissive my_custom_domain
            type my_mod_file file_type
            typeattribute my_mod_file { data_file_type core_data_file_type }
            type_transition init system_data_file file my_mod_file "custom.cfg"
            genfscon proc /custom_node u:object_r:proc_net:s0
        "#;
        let (stmts, errs) = parse_rules(doc);
        assert!(errs.is_empty(), "unexpected errors: {errs:?}");
        // 2*2*1*2 = 8 allow + 1 permissive + 1 type + 1 typeattribute + 1 trans + 1 genfscon = 13
        assert_eq!(stmts.len(), 13);
        assert!(matches!(&stmts[0], SepolicyStmt::Av { kind: AvKind::Allow, source, target, class, perm }
            if source == "init" && target == "system_file" && class == "file" && perm == "read"));
        assert!(matches!(&stmts[8], SepolicyStmt::Permissive { domain, permissive: true } if domain == "my_custom_domain"));
        assert!(matches!(&stmts[11], SepolicyStmt::TypeTransition { object_name: Some(o), .. } if o == "custom.cfg"));
    }
}
