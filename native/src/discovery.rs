// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
use napi_derive::napi;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

/// Hard cap on any file the discovery scanner is willing to slurp into
/// memory. A planted multi-GB OpenAPI / route file would otherwise blow
/// up the chariot process via OOM. 4 MiB covers every legitimate
/// OpenAPI spec observed in the public catalogs (the largest, AWS,
/// is ~3.1 MB) with headroom; oversize files are skipped with no
/// retry. Note: this is byte-count read-cap, not a content-size cap.
const MAX_DISCOVERY_FILE_BYTES: usize = 4 * 1024 * 1024;

/// Read a file into memory with a byte-count cap. Returns None when the
/// file is unreadable OR exceeds the cap. The cap is enforced by
/// `take()` so the bytes past the limit are never allocated.
fn read_capped(path: &Path) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut buf = Vec::with_capacity(8192);
    let n = f.by_ref().take(MAX_DISCOVERY_FILE_BYTES as u64 + 1).read_to_end(&mut buf).ok()?;
    if n > MAX_DISCOVERY_FILE_BYTES {
        return None;
    }
    String::from_utf8(buf).ok()
}

#[napi(object)]
#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub method: String,
    pub path: String,
    pub handler_name: Option<String>,
    pub file_path: String,
    pub line_number: u32,
}

#[napi(object)]
#[derive(Debug, Clone)]
pub struct DiscoveredService {
    pub name: String,
    pub framework: String,
    pub base_path: String,
    pub endpoints: Vec<DiscoveredEndpoint>,
    pub spec_file: Option<String>,
}

#[napi(object)]
#[derive(Debug)]
pub struct DiscoveryResult {
    pub services: Vec<DiscoveredService>,
    pub total_endpoints: u32,
    pub scan_duration_ms: u32,
}

/// Scan a codebase for OpenAPI/Swagger spec files.
/// Returns discovered services with their endpoints.
fn scan_openapi_specs(root: &Path) -> Vec<DiscoveredService> {
    let mut services = Vec::new();
    let openapi_patterns = ["openapi.json", "openapi.yaml", "openapi.yml",
                            "swagger.json", "swagger.yaml", "swagger.yml"];

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            // Skip common non-source directories
            !matches!(name.as_ref(), "node_modules" | ".git" | "dist" | "build" | "target" | ".next" | "__pycache__" | "vendor")
        })
        .filter_map(|e| e.ok())
    {
        let file_name = entry.file_name().to_string_lossy().to_lowercase();
        if !openapi_patterns.iter().any(|p| file_name == *p) {
            continue;
        }

        let file_path = entry.path().to_string_lossy().to_string();
        let content = match read_capped(entry.path()) {
            Some(c) => c,
            None => continue,
        };

        // Try to parse as JSON first, then YAML-like extraction
        if let Some(service) = parse_openapi_json(&content, &file_path) {
            services.push(service);
        } else if let Some(service) = parse_openapi_yaml_simple(&content, &file_path) {
            services.push(service);
        }
    }

    services
}

fn parse_openapi_json(content: &str, file_path: &str) -> Option<DiscoveredService> {
    let value: serde_json::Value = serde_json::from_str(content).ok()?;

    let title = value
        .pointer("/info/title")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown-service")
        .to_string();

    let paths = value.get("paths")?.as_object()?;
    let mut endpoints = Vec::new();

    for (path, methods) in paths {
        let methods_obj = methods.as_object()?;
        for (method, operation) in methods_obj {
            let http_methods = ["get", "post", "put", "patch", "delete", "head", "options"];
            if !http_methods.contains(&method.as_str()) {
                continue;
            }

            let handler_name = operation
                .get("operationId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            endpoints.push(DiscoveredEndpoint {
                method: method.to_uppercase(),
                path: path.clone(),
                handler_name,
                file_path: file_path.to_string(),
                line_number: 0,
            });
        }
    }

    if endpoints.is_empty() {
        return None;
    }

    Some(DiscoveredService {
        name: title,
        framework: "OpenAPI".to_string(),
        base_path: extract_parent_dir(file_path),
        endpoints,
        spec_file: Some(file_path.to_string()),
    })
}

fn parse_openapi_yaml_simple(content: &str, file_path: &str) -> Option<DiscoveredService> {
    // Simple YAML extraction without a full parser — looks for path patterns
    let mut title = "unknown-service".to_string();
    let mut endpoints = Vec::new();
    let mut in_paths = false;
    let mut current_path: Option<String> = None;

    for line in content.lines() {
        // Extract title
        if line.trim().starts_with("title:") {
            title = line.trim().trim_start_matches("title:").trim().trim_matches('"').trim_matches('\'').to_string();
        }

        if line == "paths:" {
            in_paths = true;
            continue;
        }

        if in_paths {
            // Top-level path (2 spaces or tab indent)
            if (line.starts_with("  /") || line.starts_with("\t/")) && line.trim().ends_with(':') {
                current_path = Some(line.trim().trim_end_matches(':').to_string());
            }

            // HTTP method (4 spaces or 2 tab indent)
            if let Some(ref path) = current_path {
                let trimmed = line.trim();
                let http_methods = ["get:", "post:", "put:", "patch:", "delete:", "head:", "options:"];
                for method in &http_methods {
                    if trimmed == *method {
                        endpoints.push(DiscoveredEndpoint {
                            method: method.trim_end_matches(':').to_uppercase(),
                            path: path.clone(),
                            handler_name: None,
                            file_path: file_path.to_string(),
                            line_number: 0,
                        });
                    }
                }
            }

            // Detect end of paths section (non-indented line that isn't empty)
            if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') && line != "paths:" {
                in_paths = false;
                current_path = None;
            }
        }
    }

    if endpoints.is_empty() {
        return None;
    }

    Some(DiscoveredService {
        name: title,
        framework: "OpenAPI".to_string(),
        base_path: extract_parent_dir(file_path),
        endpoints,
        spec_file: Some(file_path.to_string()),
    })
}

/// Scan for Express.js route definitions.
/// Looks for patterns like: app.get('/path', ...), router.post('/path', ...)
/// Remove JS/TS line (`// …`) and block (`/* … */`) comments before
/// route detection so a commented-out `app.get('/x', …)` line cannot
/// generate a phantom adapter. String and template literals are
/// preserved verbatim. Line count is preserved (comments → spaces /
/// newlines) so error reporting keeps the original line numbers.
/// Keywords whose end allows a regex literal to follow (so a `/`
/// after `return` / `if` / etc. starts a regex even though they end
/// in an identifier-letter). Mirrors the JS-grammar list used by
/// established source-map readers and devtools tokenizers.
/// Walk backward from `i` (exclusive) through a single string-literal
/// span that ends at byte i-1. Returns the index of the opening quote
/// (inclusive); the caller should continue from that index minus one.
/// Handles `\\` escape so `"\\\""` is recognized as one span.
fn skip_string_backward(bytes: &[u8], i: usize, quote: u8) -> usize {
    // bytes[i-1] is the closing quote. Walk back to find the opening
    // one whose previous char is NOT an unescaped backslash.
    let mut j = i - 1; // points at the closing quote
    while j > 0 {
        j -= 1;
        if bytes[j] == quote {
            // Count preceding backslashes; even count → unescaped.
            let mut bs = 0;
            let mut k = j;
            while k > 0 && bytes[k - 1] == b'\\' { bs += 1; k -= 1; }
            if bs % 2 == 0 { return j; }
        }
    }
    0
}

fn last_word_allows_regex(out: &str) -> bool {
    let bytes = out.as_bytes();
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b' ' | b'\t' | b'\n' | b'\r') { end -= 1; }
    if end == 0 { return true; } // start of file → regex allowed
    // Case A: previous non-space char is `)` — could be an `if (...)` /
    // `while (...)` / `for (...)` head; walk back through balanced
    // parens to the identifier before the `(`. If that identifier is
    // a regex-allowing control-flow keyword, the following `/` is a
    // regex literal even though `)` is normally an expression terminator.
    // The walk skips string and template literal spans so a `)` inside
    // a string cannot throw off the balance count.
    if bytes[end - 1] == b')' {
        let mut depth: i32 = 0;
        let mut i = end;
        while i > 0 {
            let b = bytes[i - 1];
            // Skip past a string-literal span when its closing quote
            // is at i-1. The opening quote is found by skip_string_backward.
            if b == b'"' || b == b'\'' || b == b'`' {
                let open = skip_string_backward(bytes, i, b);
                i = open; // continue with the byte BEFORE the opening quote
                continue;
            }
            if b == b')' { depth += 1; i -= 1; continue; }
            if b == b'(' {
                depth -= 1;
                i -= 1;
                if depth == 0 { break; }
                continue;
            }
            i -= 1;
        }
        return last_word_allows_regex(&out[..i]);
    }
    // Case B: collect trailing identifier word and match the keyword set.
    let mut start = end;
    while start > 0 {
        let b = bytes[start - 1];
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'$' { start -= 1; } else { break; }
    }
    if start == end {
        // Previous non-space char is an operator/punctuation — almost
        // every JS operator allows a regex on the RHS (`=`, `,`, `(`,
        // `[`, `{`, `;`, `:`, `?`, `!`, `&`, `|`, `+`, `-`, `*`, `%`,
        // `^`, `~`, `<`, `>`, `=`). Return true for the common set;
        // the regex set excludes only the expression-terminator
        // characters handled by the caller (`)`, `]`, identifier/digit).
        return true;
    }
    let word = &out[start..end];
    matches!(word,
        "return" | "typeof" | "instanceof" | "in" | "of" | "delete" | "void"
        | "throw" | "new" | "do" | "else" | "case" | "yield" | "await"
        | "if" | "while" | "for" | "switch" | "with" | "extends" | "try" | "finally")
}

fn strip_js_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    enum State { Code, LineComment, BlockComment, StringD, StringS, Template, Regex, CharClass }
    let mut state = State::Code;
    // Track the last non-space/non-newline character emitted in Code
    // state. Combined with last_word_allows_regex(), this disambiguates
    // `/` as regex-start (after keyword or operator) vs division
    // (after identifier/number/`)`/`]`).
    let mut last_code: u8 = b'\n';
    // Forward-tracked stack of identifiers that preceded each open `(`.
    // When `)` is emitted, we pop and stash the identifier in
    // last_closed_paren_kw. last_word_allows_regex() consults this on
    // the `)` branch instead of walking the buffer backward — which
    // would otherwise mis-handle nested template literals containing
    // backticks. Empty string means "no identifier preceded the `(`".
    let mut paren_kw_stack: Vec<String> = Vec::new();
    let mut last_closed_paren_kw: String = String::new();
    while i < bytes.len() {
        let c = bytes[i];
        let next = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        match state {
            State::Code => {
                if c == b'/' && next == b'/' {
                    state = State::LineComment;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                if c == b'/' && next == b'*' {
                    state = State::BlockComment;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                // Regex-literal start: `/` after a token that allows a
                // following regex (operator, keyword end, `(`, `,`,
                // `=`, `;`, `:`, `?`, `!`, `&`, `|`, `+`, `-`, `*`,
                // `%`, `^`, `~`, `<`, `>`, `{`, `[`, return/typeof,
                // OR at start of file). If `last_code` is an
                // identifier/numeric/`)`/`]` then `/` is division.
                // `/` starts a regex literal when the preceding non-space
                // token is NOT an expression-producing token (identifier,
                // number, `)`, `]`), OR when it IS an identifier but that
                // identifier is a regex-allowing keyword like `return`,
                // `if`, `typeof`, etc.
                let is_expr_terminator = matches!(last_code,
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'$' | b')' | b']');
                // For `)` use the forward-tracked closed-paren keyword
                // instead of walking the buffer backward — robust to
                // nested template literals containing backticks.
                let allows_after_close_paren = last_code == b')'
                    && matches!(last_closed_paren_kw.as_str(),
                        "if" | "while" | "for" | "switch" | "with" | "catch");
                // `]` is always an expression terminator that produces a
                // value (index / array literal end), so `/` immediately
                // after `]` is division — never a regex. Skip the
                // backward-walk fallback for that case.
                if c == b'/'
                    && (!is_expr_terminator
                        || allows_after_close_paren
                        || (last_code != b')' && last_code != b']' && last_word_allows_regex(&out)))
                {
                    state = State::Regex;
                    out.push('/');
                    last_code = b'/';
                    i += 1;
                    continue;
                }
                if c == b'"' { state = State::StringD; }
                else if c == b'\'' { state = State::StringS; }
                else if c == b'`' { state = State::Template; }
                else if c == b'(' {
                    // Snapshot the identifier immediately preceding
                    // this `(`, if any (walk back through the OUT
                    // buffer past whitespace). This buffer is
                    // string/template-safe because we only check the
                    // immediately-prior identifier word, not parens.
                    let ob = out.as_bytes();
                    let mut e = ob.len();
                    while e > 0 && matches!(ob[e - 1], b' ' | b'\t' | b'\n' | b'\r') { e -= 1; }
                    let mut s = e;
                    while s > 0 {
                        let b = ob[s - 1];
                        if b.is_ascii_alphanumeric() || b == b'_' || b == b'$' { s -= 1; } else { break; }
                    }
                    paren_kw_stack.push(out[s..e].to_string());
                } else if c == b')' {
                    last_closed_paren_kw = paren_kw_stack.pop().unwrap_or_default();
                }
                out.push(c as char);
                if c != b' ' && c != b'\t' && c != b'\n' && c != b'\r' { last_code = c; }
            }
            State::LineComment => {
                if c == b'\n' { state = State::Code; out.push('\n'); last_code = b'\n'; }
                else { out.push(' '); }
            }
            State::BlockComment => {
                if c == b'*' && next == b'/' {
                    state = State::Code;
                    out.push(' ');
                    out.push(' ');
                    last_code = b'/';
                    i += 2;
                    continue;
                }
                out.push(if c == b'\n' { '\n' } else { ' ' });
            }
            State::StringD => {
                if c == b'\\' && next != 0 { out.push(c as char); out.push(next as char); i += 2; continue; }
                if c == b'"' { state = State::Code; last_code = b'"'; out.push(c as char); i += 1; continue; }
                out.push(c as char);
            }
            State::StringS => {
                if c == b'\\' && next != 0 { out.push(c as char); out.push(next as char); i += 2; continue; }
                if c == b'\'' { state = State::Code; last_code = b'\''; out.push(c as char); i += 1; continue; }
                out.push(c as char);
            }
            State::Template => {
                if c == b'\\' && next != 0 { out.push(c as char); out.push(next as char); i += 2; continue; }
                if c == b'`' { state = State::Code; last_code = b'`'; out.push(c as char); i += 1; continue; }
                out.push(c as char);
            }
            State::Regex => {
                if c == b'\\' && next != 0 { out.push(c as char); out.push(next as char); i += 2; continue; }
                if c == b'[' { state = State::CharClass; out.push(c as char); i += 1; continue; }
                if c == b'/' { state = State::Code; last_code = b'/'; out.push(c as char); i += 1; continue; }
                if c == b'\n' { state = State::Code; last_code = b'\n'; out.push('\n'); i += 1; continue; }
                out.push(c as char);
            }
            State::CharClass => {
                if c == b'\\' && next != 0 { out.push(c as char); out.push(next as char); i += 2; continue; }
                if c == b']' { state = State::Regex; out.push(c as char); i += 1; continue; }
                if c == b'\n' { state = State::Code; last_code = b'\n'; out.push('\n'); i += 1; continue; }
                out.push(c as char);
            }
        }
        i += 1;
    }
    out
}

fn scan_express_routes(root: &Path) -> Vec<DiscoveredService> {
    // Match any identifier (1–63 [A-Za-z_][A-Za-z0-9_]* chars) calling
    // `.METHOD('path', …)`. Real Express code uses many router variable
    // names (`apiV1`, `usersRouter`, `r`, `mountPoint`); the HTTP-verb
    // method set keeps false positives like `Number.parseInt(...)` out.
    let route_pattern = regex::Regex::new(
        r#"\b[A-Za-z_][A-Za-z0-9_]{0,62}\.(get|post|put|patch|delete|head|options)\s*\(\s*['"`]([^'"`]+)['"`]"#
    ).unwrap();

    let mut service_map: std::collections::HashMap<String, Vec<DiscoveredEndpoint>> = std::collections::HashMap::new();

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !matches!(name.as_ref(), "node_modules" | ".git" | "dist" | "build" | "target" | ".next" | "__pycache__" | "vendor")
        })
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "js" | "ts" | "mjs" | "cjs") {
            continue;
        }

        let content = match read_capped(path) {
            Some(c) => c,
            None => continue,
        };

        // Quick check — skip files that don't look like route files
        if !content.contains(".get(") && !content.contains(".post(") && !content.contains(".put(")
            && !content.contains(".patch(") && !content.contains(".delete(") {
            continue;
        }

        let stripped = strip_js_comments(&content);

        let file_path = path.to_string_lossy().to_string();
        let service_name = infer_service_name(path);

        for (line_number, line) in stripped.lines().enumerate() {
            for cap in route_pattern.captures_iter(line) {
                let method = cap[1].to_uppercase();
                let route_path = cap[2].to_string();

                service_map
                    .entry(service_name.clone())
                    .or_default()
                    .push(DiscoveredEndpoint {
                        method,
                        path: route_path,
                        handler_name: None,
                        file_path: file_path.clone(),
                        line_number: (line_number + 1) as u32,
                    });
            }
        }
    }

    service_map
        .into_iter()
        .filter(|(_, endpoints)| !endpoints.is_empty())
        .map(|(name, endpoints)| {
            let base_path = endpoints
                .first()
                .map(|e| extract_parent_dir(&e.file_path))
                .unwrap_or_default();
            DiscoveredService {
                name,
                framework: "Express".to_string(),
                base_path,
                endpoints,
                spec_file: None,
            }
        })
        .collect()
}

fn infer_service_name(path: &Path) -> String {
    // Try to derive a service name from the file path
    // e.g., src/routes/payments.ts → "payments"
    // e.g., services/user-service/routes.ts → "user-service"
    let components: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();

    // Look for common directory patterns
    for (i, component) in components.iter().enumerate() {
        if matches!(*component, "routes" | "controllers" | "api" | "handlers") {
            // Use the next component (file name) or previous (directory name)
            if i + 1 < components.len() {
                let name = components[i + 1];
                return name
                    .trim_end_matches(".ts")
                    .trim_end_matches(".js")
                    .trim_end_matches(".mjs")
                    .to_string();
            }
            if i > 0 {
                return components[i - 1].to_string();
            }
        }
    }

    // Fallback: use the file stem
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn extract_parent_dir(file_path: &str) -> String {
    Path::new(file_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Scan a codebase directory for internal APIs.
/// Currently supports: OpenAPI/Swagger specs, Express.js route definitions.
/// Returns structured discovery results for the CLI to present.
#[napi]
pub fn discover_internal_apis(codebase_path: String) -> DiscoveryResult {
    let start = std::time::Instant::now();
    let root = Path::new(&codebase_path);

    if !root.exists() || !root.is_dir() {
        return DiscoveryResult {
            services: vec![],
            total_endpoints: 0,
            scan_duration_ms: start.elapsed().as_millis() as u32,
        };
    }

    let mut services = Vec::new();

    // Scan for OpenAPI specs first (highest confidence)
    services.extend(scan_openapi_specs(root));

    // Scan for Express route definitions
    services.extend(scan_express_routes(root));

    let total_endpoints: u32 = services.iter().map(|s| s.endpoints.len() as u32).sum();

    DiscoveryResult {
        services,
        total_endpoints,
        scan_duration_ms: start.elapsed().as_millis() as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_keeps_route_after_return_regex() {
        let src = "function h() { return /foo/.test(x); }\napp.get('/users', () => {});\n";
        let out = strip_js_comments(src);
        assert!(out.contains("app.get('/users'"), "route survived regex disambig: {}", out);
    }

    #[test]
    fn strip_keeps_route_after_if_paren_regex() {
        let src = "if (cond) /foo/.test(x);\nrouter.post('/login', h);\n";
        let out = strip_js_comments(src);
        assert!(out.contains("router.post('/login'"), "route survived if-paren regex: {}", out);
    }

    #[test]
    fn strip_drops_line_comment_route() {
        let src = "// app.get('/bogus', h)\napp.get('/real', h);\n";
        let out = strip_js_comments(src);
        assert!(!out.contains("'/bogus'"), "commented route dropped");
        assert!(out.contains("app.get('/real'"), "real route kept");
    }

    #[test]
    fn strip_handles_regex_containing_slash() {
        let src = "const r = /[/]/;\napp.get('/x', h);\n";
        let out = strip_js_comments(src);
        assert!(out.contains("app.get('/x'"), "route after regex literal containing slash: {}", out);
    }

    #[test]
    fn strip_paren_balance_skips_string_paren() {
        // foo(")") /re/ — embedded `)` inside a string must not throw
        // off the paren-balance walk used by last_word_allows_regex.
        // Here the `/re/` is division-like (after a function-call
        // result), so the route on the next line must still survive.
        let src = "foo(\")\") / 2;\napp.get('/balance', h);\n";
        let out = strip_js_comments(src);
        assert!(out.contains("app.get('/balance'"), "route survived paren-string mix: {}", out);
    }

    #[test]
    fn strip_array_index_division_not_regex() {
        // arr[i] / 2 — `]` is an expression terminator; the `/`
        // must be division, not regex-start.
        let src = "const r = arr[i] / 2;\napp.get('/idx', h);\n";
        let out = strip_js_comments(src);
        assert!(out.contains("app.get('/idx'"), "route after array-index division: {}", out);
    }

    #[test]
    fn strip_call_index_division_not_regex() {
        // foo()[0] / 2 — same case via call-then-index.
        let src = "const r = foo()[0] / 2;\nrouter.post('/calldiv', h);\n";
        let out = strip_js_comments(src);
        assert!(out.contains("router.post('/calldiv'"), "route after call-index division: {}", out);
    }

    #[test]
    fn strip_nested_template_with_backticks() {
        // Nested template literal: outer template contains ${nested}
        // expression which itself contains a backtick'd template
        // literal. Paren-balance must not get confused by interior
        // backticks because the forward-tracked paren-keyword stack
        // doesn't backward-scan strings/templates at all.
        let src = "const s = `outer ${`inner`} end`;\nif (cond) /re/.test(x);\napp.get('/nest', h);\n";
        let out = strip_js_comments(src);
        assert!(out.contains("app.get('/nest'"), "route survived nested template: {}", out);
    }

    #[test]
    fn strip_paren_balance_with_string_keyword() {
        // if (")") /re/.test(x) — paren-balance must walk past the
        // string and find `if` so the `/` is recognized as regex.
        let src = "if (\")\") /re/.test(x);\napp.get('/kw', h);\n";
        let out = strip_js_comments(src);
        assert!(out.contains("app.get('/kw'"), "route survived if-string-paren regex: {}", out);
    }

    #[test]
    fn strip_division_not_regex() {
        // `count / interval` is division, not a regex — last_code is
        // 't' (identifier letter) so last_word_allows_regex returns
        // false. The string should pass through unchanged.
        let src = "let r = count / interval;\napp.get('/y', h);\n";
        let out = strip_js_comments(src);
        assert!(out.contains("app.get('/y'"), "route after division: {}", out);
    }
}
