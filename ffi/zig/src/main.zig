// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// hpm-github-api-rsr — composite GitHub App API client.
//
// Composes three sibling RSR libraries via C ABI:
//   * libhpm_crypto       — RS256 signing + base64url
//   * libhpm_http_client  — HTTPS via std.http.Client
//   * libhpm_json         — JSON parse + escape
//
// Exports a token + 7-operation REST surface tailored to the OikosBot
// AffineScript port (Phase 5). All authenticated requests inject the
// canonical GitHub headers:
//   Accept:        application/vnd.github+json
//   X-GitHub-Api-Version: 2022-11-28
//   User-Agent:    hpm-github-api-rsr/0.1

const std = @import("std");

//==============================================================================
// Extern declarations (sibling FFI surface)
//==============================================================================

extern fn hpm_crypto_base64url_encode(
    in_ptr: ?[*]const u8,
    in_len: usize,
    out_ptr: ?[*]u8,
    out_cap: usize,
) isize;

extern fn hpm_crypto_rs256_sign(
    pem_ptr: ?[*]const u8,
    pem_len: usize,
    msg_ptr: ?[*]const u8,
    msg_len: usize,
    sig_out: ?[*]u8,
    sig_cap: usize,
) isize;

const HpmHttpClient = opaque {};
const HpmHttpResponse = opaque {};

extern fn hpm_http_client_new() ?*HpmHttpClient;
extern fn hpm_http_client_free(client: ?*HpmHttpClient) void;
extern fn hpm_http_client_request(
    client: ?*HpmHttpClient,
    method_ordinal: c_int,
    url_ptr: ?[*]const u8,
    url_len: usize,
    extra_headers_ptr: ?[*]const u8,
    extra_headers_len: usize,
    body_ptr: ?[*]const u8,
    body_len: usize,
) ?*HpmHttpResponse;
extern fn hpm_http_response_status(resp: ?*HpmHttpResponse) c_int;
extern fn hpm_http_response_body(resp: ?*HpmHttpResponse, out: ?[*]u8, cap: usize) isize;
extern fn hpm_http_response_free(resp: ?*HpmHttpResponse) void;

const HpmJsonValue = opaque {};

extern fn hpm_json_parse(src: ?[*]const u8, src_len: usize) ?*HpmJsonValue;
extern fn hpm_json_free(v: ?*HpmJsonValue) void;
extern fn hpm_json_object_get(v: ?*HpmJsonValue, key: ?[*]const u8, key_len: usize) ?*HpmJsonValue;
extern fn hpm_json_string(v: ?*HpmJsonValue, out: ?[*]u8, cap: usize) isize;
extern fn hpm_json_escape_string(
    src: ?[*]const u8,
    src_len: usize,
    out: ?[*]u8,
    cap: usize,
) isize;

//==============================================================================
// Public handle types
//==============================================================================

/// Heap-allocated NUL-terminated token. Used for both JWTs and
/// installation access tokens — the call-site distinguishes by which
/// function produced it.
pub const HpmGithubToken = struct {
    allocator: std.mem.Allocator,
    bytes: []u8, // not NUL-terminated; len == strlen
};

/// Heap-allocated response (status + body slice).
pub const HpmGithubResponse = struct {
    allocator: std.mem.Allocator,
    status: c_int,
    body: []u8,
};

//==============================================================================
// Internal helpers
//==============================================================================

const ACCEPT_HEADER = "Accept: application/vnd.github+json\r\n";
const API_VERSION_HEADER = "X-GitHub-Api-Version: 2022-11-28\r\n";
const USER_AGENT_HEADER = "User-Agent: hpm-github-api-rsr/0.1\r\n";
const COMMON_HEADERS = ACCEPT_HEADER ++ API_VERSION_HEADER ++ USER_AGENT_HEADER;
const CONTENT_TYPE_JSON = "Content-Type: application/json\r\n";

const METHOD_GET: c_int = 0;
const METHOD_POST: c_int = 2;
const METHOD_PATCH: c_int = 8;

const MAX_URL_LEN: usize = 1024;
const MAX_HEADERS_LEN: usize = 4096;

/// base64url-encode `input` into an allocator-backed slice.
fn b64UrlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const required = hpm_crypto_base64url_encode(
        input.ptr,
        input.len,
        null,
        0,
    );
    if (required < 0) return error.Base64UrlEncode;
    const out = try allocator.alloc(u8, @intCast(required));
    errdefer allocator.free(out);
    const wrote = hpm_crypto_base64url_encode(
        input.ptr,
        input.len,
        out.ptr,
        out.len,
    );
    if (wrote < 0 or @as(usize, @intCast(wrote)) != out.len) return error.Base64UrlEncode;
    return out;
}

/// Build the GitHub App JWT for `app_id` using the PKCS#8 PEM private
/// key. `now` is the Unix timestamp; `lifetime_seconds` clamps to
/// GitHub's 10-minute ceiling.
fn buildJwt(
    allocator: std.mem.Allocator,
    app_id: []const u8,
    pem: []const u8,
    now: i64,
    lifetime_seconds: i64,
) ![]u8 {
    const exp_offset: i64 = if (lifetime_seconds > 600) 600 else lifetime_seconds;

    const header_json = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

    var payload_buf: [256]u8 = undefined;
    const payload_json = try std.fmt.bufPrint(
        &payload_buf,
        "{{\"iat\":{d},\"exp\":{d},\"iss\":\"{s}\"}}",
        .{ now, now + exp_offset, app_id },
    );

    const header_b64 = try b64UrlEncode(allocator, header_json);
    defer allocator.free(header_b64);
    const payload_b64 = try b64UrlEncode(allocator, payload_json);
    defer allocator.free(payload_b64);

    var msg = try allocator.alloc(u8, header_b64.len + 1 + payload_b64.len);
    defer allocator.free(msg);
    @memcpy(msg[0..header_b64.len], header_b64);
    msg[header_b64.len] = '.';
    @memcpy(msg[header_b64.len + 1 ..], payload_b64);

    var sig_bytes: [256]u8 = undefined;
    const sig_rc = hpm_crypto_rs256_sign(
        pem.ptr,
        pem.len,
        msg.ptr,
        msg.len,
        &sig_bytes,
        sig_bytes.len,
    );
    if (sig_rc != 256) return error.Rs256Sign;

    const sig_b64 = try b64UrlEncode(allocator, &sig_bytes);
    defer allocator.free(sig_b64);

    var jwt = try allocator.alloc(u8, msg.len + 1 + sig_b64.len);
    @memcpy(jwt[0..msg.len], msg);
    jwt[msg.len] = '.';
    @memcpy(jwt[msg.len + 1 ..], sig_b64);
    return jwt;
}

/// Build the headers buffer for a request authed with a Bearer token.
/// `extra` may contain additional CRLF-separated headers (e.g.
/// Content-Type). Caller owns the returned slice.
fn buildHeaders(
    allocator: std.mem.Allocator,
    bearer_token: []const u8,
    extra: []const u8,
) ![]u8 {
    return try std.fmt.allocPrint(
        allocator,
        "Authorization: Bearer {s}\r\n" ++ COMMON_HEADERS ++ "{s}",
        .{ bearer_token, extra },
    );
}

/// Perform a request and return a wrapped response. The
/// returned struct's `body` is owned by `allocator`.
fn doRequest(
    allocator: std.mem.Allocator,
    method: c_int,
    url: []const u8,
    headers: []const u8,
    body: []const u8,
) !*HpmGithubResponse {
    const client = hpm_http_client_new() orelse return error.ClientNew;
    defer hpm_http_client_free(client);

    const body_ptr: ?[*]const u8 = if (body.len > 0) body.ptr else null;

    const resp = hpm_http_client_request(
        client,
        method,
        url.ptr,
        url.len,
        headers.ptr,
        headers.len,
        body_ptr,
        body.len,
    ) orelse return error.RequestFailed;
    defer hpm_http_response_free(resp);

    const status = hpm_http_response_status(resp);
    const body_len_rc = hpm_http_response_body(resp, null, 0);
    if (body_len_rc < 0) return error.BodyRead;
    const body_len: usize = @intCast(body_len_rc);

    const body_copy = try allocator.alloc(u8, body_len);
    errdefer allocator.free(body_copy);
    if (body_len > 0) {
        const wrote = hpm_http_response_body(resp, body_copy.ptr, body_copy.len);
        if (wrote < 0 or @as(usize, @intCast(wrote)) != body_len) return error.BodyRead;
    }

    const wrapper = try allocator.create(HpmGithubResponse);
    wrapper.* = .{
        .allocator = allocator,
        .status = status,
        .body = body_copy,
    };
    return wrapper;
}

/// Read a string field from a JSON response. Caller owns the slice.
fn readJsonString(
    allocator: std.mem.Allocator,
    json_bytes: []const u8,
    key: []const u8,
) ![]u8 {
    const root = hpm_json_parse(json_bytes.ptr, json_bytes.len) orelse return error.JsonParse;
    defer hpm_json_free(root);
    const field = hpm_json_object_get(root, key.ptr, key.len) orelse return error.JsonKeyMissing;
    defer hpm_json_free(field);

    const required = hpm_json_string(field, null, 0);
    if (required < 0) return error.JsonTypeMismatch;
    const out = try allocator.alloc(u8, @intCast(required));
    errdefer allocator.free(out);
    const wrote = hpm_json_string(field, out.ptr, out.len);
    if (wrote < 0) return error.JsonReadString;
    return out;
}

/// JSON-escape a string into an allocator-backed slice (no surrounding quotes).
fn escapeJsonString(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const required = hpm_json_escape_string(input.ptr, input.len, null, 0);
    if (required < 0) return error.JsonEscape;
    const out = try allocator.alloc(u8, @intCast(required));
    errdefer allocator.free(out);
    const wrote = hpm_json_escape_string(input.ptr, input.len, out.ptr, out.len);
    if (wrote < 0) return error.JsonEscape;
    return out;
}

//==============================================================================
// Public exports
//==============================================================================

/// Generate a GitHub App JWT.
///
/// `app_id` is the App's numeric ID as a decimal string.
/// `pem` is the PKCS#8-PEM-encoded RSA-2048 private key.
/// `lifetime_seconds` is clamped to GitHub's 10-minute (600 s) ceiling.
///
/// Returns NULL on RS256/base64url/alloc failure.
export fn hpm_github_app_generate_jwt(
    app_id_ptr: ?[*]const u8,
    app_id_len: usize,
    pem_ptr: ?[*]const u8,
    pem_len: usize,
    lifetime_seconds: i64,
) ?*HpmGithubToken {
    if (app_id_ptr == null or app_id_len == 0) return null;
    if (pem_ptr == null or pem_len == 0) return null;

    const allocator = std.heap.c_allocator;
    const app_id = app_id_ptr.?[0..app_id_len];
    const pem = pem_ptr.?[0..pem_len];

    const jwt_bytes = buildJwt(
        allocator,
        app_id,
        pem,
        std.time.timestamp(),
        lifetime_seconds,
    ) catch return null;
    errdefer allocator.free(jwt_bytes);

    const token = allocator.create(HpmGithubToken) catch return null;
    token.* = .{ .allocator = allocator, .bytes = jwt_bytes };
    return token;
}

/// Exchange a JWT for an installation access token.
///
/// `installation_id` is the installation's numeric ID.
/// Returns NULL on HTTP / JSON / non-2xx failure.
export fn hpm_github_app_get_installation_token(
    jwt: ?*HpmGithubToken,
    installation_id: i64,
) ?*HpmGithubToken {
    const j = jwt orelse return null;
    const allocator = std.heap.c_allocator;

    var url_buf: [MAX_URL_LEN]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://api.github.com/app/installations/{d}/access_tokens",
        .{installation_id},
    ) catch return null;

    const headers = buildHeaders(allocator, j.bytes, "") catch return null;
    defer allocator.free(headers);

    const resp = doRequest(allocator, METHOD_POST, url, headers, &[_]u8{}) catch return null;
    defer hpm_github_response_free(resp);

    if (resp.status < 200 or resp.status >= 300) return null;

    const token_str = readJsonString(allocator, resp.body, "token") catch return null;
    errdefer allocator.free(token_str);

    const token = allocator.create(HpmGithubToken) catch return null;
    token.* = .{ .allocator = allocator, .bytes = token_str };
    return token;
}

/// POST a comment on an issue / PR.
export fn hpm_github_post_pr_comment(
    token: ?*HpmGithubToken,
    owner_ptr: ?[*]const u8,
    owner_len: usize,
    repo_ptr: ?[*]const u8,
    repo_len: usize,
    issue_number: i64,
    body_ptr: ?[*]const u8,
    body_len: usize,
) ?*HpmGithubResponse {
    const t = token orelse return null;
    if (owner_ptr == null or owner_len == 0) return null;
    if (repo_ptr == null or repo_len == 0) return null;
    if (body_ptr == null) return null;

    const allocator = std.heap.c_allocator;
    const owner = owner_ptr.?[0..owner_len];
    const repo = repo_ptr.?[0..repo_len];
    const body = body_ptr.?[0..body_len];

    var url_buf: [MAX_URL_LEN]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://api.github.com/repos/{s}/{s}/issues/{d}/comments",
        .{ owner, repo, issue_number },
    ) catch return null;

    const escaped = escapeJsonString(allocator, body) catch return null;
    defer allocator.free(escaped);
    const json_body = std.fmt.allocPrint(
        allocator,
        "{{\"body\":\"{s}\"}}",
        .{escaped},
    ) catch return null;
    defer allocator.free(json_body);

    const headers = buildHeaders(allocator, t.bytes, CONTENT_TYPE_JSON) catch return null;
    defer allocator.free(headers);

    return doRequest(allocator, METHOD_POST, url, headers, json_body) catch null;
}

/// PATCH an issue comment by ID.
export fn hpm_github_update_comment(
    token: ?*HpmGithubToken,
    owner_ptr: ?[*]const u8,
    owner_len: usize,
    repo_ptr: ?[*]const u8,
    repo_len: usize,
    comment_id: i64,
    body_ptr: ?[*]const u8,
    body_len: usize,
) ?*HpmGithubResponse {
    const t = token orelse return null;
    if (owner_ptr == null or owner_len == 0) return null;
    if (repo_ptr == null or repo_len == 0) return null;
    if (body_ptr == null) return null;

    const allocator = std.heap.c_allocator;
    const owner = owner_ptr.?[0..owner_len];
    const repo = repo_ptr.?[0..repo_len];
    const body = body_ptr.?[0..body_len];

    var url_buf: [MAX_URL_LEN]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://api.github.com/repos/{s}/{s}/issues/comments/{d}",
        .{ owner, repo, comment_id },
    ) catch return null;

    const escaped = escapeJsonString(allocator, body) catch return null;
    defer allocator.free(escaped);
    const json_body = std.fmt.allocPrint(
        allocator,
        "{{\"body\":\"{s}\"}}",
        .{escaped},
    ) catch return null;
    defer allocator.free(json_body);

    const headers = buildHeaders(allocator, t.bytes, CONTENT_TYPE_JSON) catch return null;
    defer allocator.free(headers);

    return doRequest(allocator, METHOD_PATCH, url, headers, json_body) catch null;
}

/// Create a check-run for `head_sha`.
///
/// `status` and `conclusion` may be empty strings (NULL or len 0) to
/// omit them.
export fn hpm_github_create_check_run(
    token: ?*HpmGithubToken,
    owner_ptr: ?[*]const u8,
    owner_len: usize,
    repo_ptr: ?[*]const u8,
    repo_len: usize,
    name_ptr: ?[*]const u8,
    name_len: usize,
    head_sha_ptr: ?[*]const u8,
    head_sha_len: usize,
    status_ptr: ?[*]const u8,
    status_len: usize,
    conclusion_ptr: ?[*]const u8,
    conclusion_len: usize,
) ?*HpmGithubResponse {
    const t = token orelse return null;
    if (owner_ptr == null or owner_len == 0) return null;
    if (repo_ptr == null or repo_len == 0) return null;
    if (name_ptr == null or name_len == 0) return null;
    if (head_sha_ptr == null or head_sha_len == 0) return null;

    const allocator = std.heap.c_allocator;
    const owner = owner_ptr.?[0..owner_len];
    const repo = repo_ptr.?[0..repo_len];
    const name = name_ptr.?[0..name_len];
    const head_sha = head_sha_ptr.?[0..head_sha_len];

    var url_buf: [MAX_URL_LEN]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://api.github.com/repos/{s}/{s}/check-runs",
        .{ owner, repo },
    ) catch return null;

    // Build JSON body. Always includes name + head_sha; conditionally
    // adds status and conclusion.
    var body_buf = std.ArrayList(u8){};
    defer body_buf.deinit(allocator);

    const name_esc = escapeJsonString(allocator, name) catch return null;
    defer allocator.free(name_esc);
    const sha_esc = escapeJsonString(allocator, head_sha) catch return null;
    defer allocator.free(sha_esc);

    body_buf.appendSlice(allocator, "{\"name\":\"") catch return null;
    body_buf.appendSlice(allocator, name_esc) catch return null;
    body_buf.appendSlice(allocator, "\",\"head_sha\":\"") catch return null;
    body_buf.appendSlice(allocator, sha_esc) catch return null;
    body_buf.appendSlice(allocator, "\"") catch return null;

    if (status_ptr != null and status_len > 0) {
        const status_slice = status_ptr.?[0..status_len];
        const status_esc = escapeJsonString(allocator, status_slice) catch return null;
        defer allocator.free(status_esc);
        body_buf.appendSlice(allocator, ",\"status\":\"") catch return null;
        body_buf.appendSlice(allocator, status_esc) catch return null;
        body_buf.appendSlice(allocator, "\"") catch return null;
    }
    if (conclusion_ptr != null and conclusion_len > 0) {
        const conc_slice = conclusion_ptr.?[0..conclusion_len];
        const conc_esc = escapeJsonString(allocator, conc_slice) catch return null;
        defer allocator.free(conc_esc);
        body_buf.appendSlice(allocator, ",\"conclusion\":\"") catch return null;
        body_buf.appendSlice(allocator, conc_esc) catch return null;
        body_buf.appendSlice(allocator, "\"") catch return null;
    }
    body_buf.appendSlice(allocator, "}") catch return null;

    const headers = buildHeaders(allocator, t.bytes, CONTENT_TYPE_JSON) catch return null;
    defer allocator.free(headers);

    return doRequest(allocator, METHOD_POST, url, headers, body_buf.items) catch null;
}

/// GET a single pull request.
export fn hpm_github_get_pull_request(
    token: ?*HpmGithubToken,
    owner_ptr: ?[*]const u8,
    owner_len: usize,
    repo_ptr: ?[*]const u8,
    repo_len: usize,
    pr_number: i64,
) ?*HpmGithubResponse {
    const t = token orelse return null;
    if (owner_ptr == null or owner_len == 0) return null;
    if (repo_ptr == null or repo_len == 0) return null;

    const allocator = std.heap.c_allocator;
    const owner = owner_ptr.?[0..owner_len];
    const repo = repo_ptr.?[0..repo_len];

    var url_buf: [MAX_URL_LEN]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://api.github.com/repos/{s}/{s}/pulls/{d}",
        .{ owner, repo, pr_number },
    ) catch return null;

    const headers = buildHeaders(allocator, t.bytes, "") catch return null;
    defer allocator.free(headers);

    return doRequest(allocator, METHOD_GET, url, headers, &[_]u8{}) catch null;
}

/// GET repository metadata.
export fn hpm_github_get_repository(
    token: ?*HpmGithubToken,
    owner_ptr: ?[*]const u8,
    owner_len: usize,
    repo_ptr: ?[*]const u8,
    repo_len: usize,
) ?*HpmGithubResponse {
    const t = token orelse return null;
    if (owner_ptr == null or owner_len == 0) return null;
    if (repo_ptr == null or repo_len == 0) return null;

    const allocator = std.heap.c_allocator;
    const owner = owner_ptr.?[0..owner_len];
    const repo = repo_ptr.?[0..repo_len];

    var url_buf: [MAX_URL_LEN]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://api.github.com/repos/{s}/{s}",
        .{ owner, repo },
    ) catch return null;

    const headers = buildHeaders(allocator, t.bytes, "") catch return null;
    defer allocator.free(headers);

    return doRequest(allocator, METHOD_GET, url, headers, &[_]u8{}) catch null;
}

//==============================================================================
// Lifecycle + accessors
//==============================================================================

/// Read the raw token bytes. Returns bytes written, required size when
/// `cap == 0`, or -1 on NULL.
export fn hpm_github_token_bytes(
    token: ?*HpmGithubToken,
    out: ?[*]u8,
    cap: usize,
) isize {
    const t = token orelse return -1;
    if (out == null or cap == 0) return @intCast(t.bytes.len);
    if (cap < t.bytes.len) return -1;
    @memcpy(out.?[0..t.bytes.len], t.bytes);
    return @intCast(t.bytes.len);
}

export fn hpm_github_token_free(token: ?*HpmGithubToken) void {
    const t = token orelse return;
    t.allocator.free(t.bytes);
    t.allocator.destroy(t);
}

export fn hpm_github_response_status_get(resp: ?*HpmGithubResponse) c_int {
    const r = resp orelse return -1;
    return r.status;
}

export fn hpm_github_response_body_get(
    resp: ?*HpmGithubResponse,
    out: ?[*]u8,
    cap: usize,
) isize {
    const r = resp orelse return -1;
    if (out == null or cap == 0) return @intCast(r.body.len);
    if (cap < r.body.len) return -1;
    @memcpy(out.?[0..r.body.len], r.body);
    return @intCast(r.body.len);
}

export fn hpm_github_response_free(resp: ?*HpmGithubResponse) void {
    const r = resp orelse return;
    r.allocator.free(r.body);
    r.allocator.destroy(r);
}

//==============================================================================
// Tests
//==============================================================================
//
// Most tests exercise the offline path (JWT construction + base64url).
// The network ops are exercised by the OikosBot consumer against the
// real GitHub API once Phase 5 lands; building a full GH-API mock here
// would duplicate the sibling http-client tests.

const testing = std.testing;

// PKCS#8 PEM test key (RSA-2048). Same constant as hpm-crypto-rsr tests.
const TEST_PEM =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
    \\MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
    \\NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
    \\qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
    \\p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
    \\ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
    \\VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
    \\laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
    \\sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
    \\mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
    \\dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
    \\ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
    \\DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
    \\N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
    \\0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
    \\t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
    \\AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
    \\48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
    \\DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
    \\xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
    \\mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
    \\2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
    \\et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
    \\VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
    \\TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
    \\dn/RsYEONbwQSjIfMPkvxF+8HQ==
    \\-----END PRIVATE KEY-----
    \\
;

test "buildJwt produces three dot-separated base64url segments" {
    const allocator = testing.allocator;
    const jwt = try buildJwt(allocator, "12345", TEST_PEM, 1_700_000_000, 600);
    defer allocator.free(jwt);

    var dot_count: usize = 0;
    for (jwt) |c| if (c == '.') {
        dot_count += 1;
    };
    try testing.expectEqual(@as(usize, 2), dot_count);

    // base64url alphabet: A-Z a-z 0-9 - _ (no padding, no '+' or '/')
    for (jwt) |c| {
        const ok = (c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.';
        try testing.expect(ok);
    }
}

test "buildJwt clamps lifetime to 600 seconds" {
    const allocator = testing.allocator;
    const jwt_900 = try buildJwt(allocator, "1", TEST_PEM, 1_700_000_000, 900);
    defer allocator.free(jwt_900);
    const jwt_600 = try buildJwt(allocator, "1", TEST_PEM, 1_700_000_000, 600);
    defer allocator.free(jwt_600);

    // Same iat / app_id / clamp target ⇒ identical JWTs.
    try testing.expectEqualSlices(u8, jwt_600, jwt_900);
}

test "buildJwt encodes the app_id in the payload" {
    const allocator = testing.allocator;
    const jwt = try buildJwt(allocator, "98765", TEST_PEM, 1_700_000_000, 60);
    defer allocator.free(jwt);

    // Decode the middle segment (payload) and verify "98765" appears.
    var dot1: usize = 0;
    while (dot1 < jwt.len and jwt[dot1] != '.') : (dot1 += 1) {}
    try testing.expect(dot1 < jwt.len);
    var dot2: usize = dot1 + 1;
    while (dot2 < jwt.len and jwt[dot2] != '.') : (dot2 += 1) {}
    try testing.expect(dot2 < jwt.len);
    const payload_b64 = jwt[dot1 + 1 .. dot2];

    // base64url decode by padding back to base64 + std decode.
    const padding_needed = (4 - (payload_b64.len % 4)) % 4;
    var pad_buf: [4]u8 = .{ '=', '=', '=', '=' };
    var padded_b64 = std.ArrayList(u8){};
    defer padded_b64.deinit(allocator);
    for (payload_b64) |c| {
        const mapped: u8 = switch (c) {
            '-' => '+',
            '_' => '/',
            else => c,
        };
        try padded_b64.append(allocator, mapped);
    }
    try padded_b64.appendSlice(allocator, pad_buf[0..padding_needed]);

    var payload_buf: [256]u8 = undefined;
    const decoder = std.base64.standard.Decoder;
    const dec_len = decoder.calcSizeForSlice(padded_b64.items) catch unreachable;
    try decoder.decode(payload_buf[0..dec_len], padded_b64.items);
    const decoded = payload_buf[0..dec_len];

    try testing.expect(std.mem.indexOf(u8, decoded, "98765") != null);
    try testing.expect(std.mem.indexOf(u8, decoded, "\"iat\":1700000000") != null);
    try testing.expect(std.mem.indexOf(u8, decoded, "\"exp\":1700000060") != null);
}

test "hpm_github_app_generate_jwt round-trip through bytes accessor" {
    const tok = hpm_github_app_generate_jwt(
        "42",
        2,
        TEST_PEM.ptr,
        TEST_PEM.len,
        300,
    );
    try testing.expect(tok != null);
    defer hpm_github_token_free(tok);

    const required = hpm_github_token_bytes(tok, null, 0);
    try testing.expect(required > 0);

    const out = try testing.allocator.alloc(u8, @intCast(required));
    defer testing.allocator.free(out);
    const wrote = hpm_github_token_bytes(tok, out.ptr, out.len);
    try testing.expectEqual(required, wrote);

    // Two dots = three segments.
    var dots: usize = 0;
    for (out) |c| if (c == '.') {
        dots += 1;
    };
    try testing.expectEqual(@as(usize, 2), dots);
}

test "hpm_github_app_generate_jwt rejects null pem" {
    const tok = hpm_github_app_generate_jwt("42", 2, null, 0, 60);
    try testing.expect(tok == null);
}

test "hpm_github_app_generate_jwt rejects empty app_id" {
    const tok = hpm_github_app_generate_jwt(null, 0, TEST_PEM.ptr, TEST_PEM.len, 60);
    try testing.expect(tok == null);
}

test "escapeJsonString escapes quotes and backslashes" {
    const escaped = try escapeJsonString(testing.allocator, "he said \"hi\\\"");
    defer testing.allocator.free(escaped);
    try testing.expectEqualSlices(u8, "he said \\\"hi\\\\\\\"", escaped);
}

test "buildHeaders includes the bearer token and common headers" {
    const headers = try buildHeaders(testing.allocator, "xxx.yyy.zzz", "");
    defer testing.allocator.free(headers);
    try testing.expect(std.mem.indexOf(u8, headers, "Authorization: Bearer xxx.yyy.zzz\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, headers, "Accept: application/vnd.github+json\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, headers, "X-GitHub-Api-Version: 2022-11-28\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, headers, "User-Agent: hpm-github-api-rsr/0.1\r\n") != null);
}

test "buildHeaders appends extra-headers verbatim" {
    const headers = try buildHeaders(testing.allocator, "t", "X-Custom: 1\r\n");
    defer testing.allocator.free(headers);
    try testing.expect(std.mem.indexOf(u8, headers, "X-Custom: 1\r\n") != null);
}

test "readJsonString extracts a field" {
    const json_bytes = "{\"token\":\"ghs_abc123\",\"expires_at\":\"2026-05-28T00:00:00Z\"}";
    const tok = try readJsonString(testing.allocator, json_bytes, "token");
    defer testing.allocator.free(tok);
    try testing.expectEqualSlices(u8, "ghs_abc123", tok);
}

test "readJsonString returns error on missing field" {
    const json_bytes = "{\"other\":\"x\"}";
    const result = readJsonString(testing.allocator, json_bytes, "token");
    try testing.expectError(error.JsonKeyMissing, result);
}
