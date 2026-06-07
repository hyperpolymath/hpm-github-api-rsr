<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
<!-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk> -->

# hpm-github-api-rsr ABI/FFI Documentation

Composes three sibling RSR libraries:
* `libhpm_crypto` — RS256 + base64url
* `libhpm_http_client` — HTTPS via `std.http.Client`
* `libhpm_json` — parse + escape

## C ABI surface

```c
// JWT generation (composes crypto + base64url + json text construction)
hpm_github_token_t* hpm_github_app_generate_jwt(
    const uint8_t* app_id, size_t app_id_len,
    const uint8_t* pem, size_t pem_len,
    int64_t lifetime_seconds);   // clamped to 600 (GitHub's ceiling)

// Installation-token exchange (composes JWT + http-client + json parse)
hpm_github_token_t* hpm_github_app_get_installation_token(
    hpm_github_token_t* jwt, int64_t installation_id);

// REST ops (each composes http-client + json escape for body construction)
hpm_github_response_t* hpm_github_post_pr_comment(
    hpm_github_token_t* token,
    const uint8_t* owner, size_t owner_len,
    const uint8_t* repo, size_t repo_len,
    int64_t issue_number,
    const uint8_t* body, size_t body_len);

hpm_github_response_t* hpm_github_update_comment(
    hpm_github_token_t* token,
    const uint8_t* owner, size_t owner_len,
    const uint8_t* repo, size_t repo_len,
    int64_t comment_id,
    const uint8_t* body, size_t body_len);

hpm_github_response_t* hpm_github_create_check_run(
    hpm_github_token_t* token,
    const uint8_t* owner, size_t owner_len,
    const uint8_t* repo, size_t repo_len,
    const uint8_t* name, size_t name_len,
    const uint8_t* head_sha, size_t head_sha_len,
    const uint8_t* status, size_t status_len,         // may be NULL/0 to omit
    const uint8_t* conclusion, size_t conclusion_len);// may be NULL/0 to omit

hpm_github_response_t* hpm_github_get_pull_request(
    hpm_github_token_t* token,
    const uint8_t* owner, size_t owner_len,
    const uint8_t* repo, size_t repo_len,
    int64_t pr_number);

hpm_github_response_t* hpm_github_get_repository(
    hpm_github_token_t* token,
    const uint8_t* owner, size_t owner_len,
    const uint8_t* repo, size_t repo_len);

// Accessors + lifecycle
ssize_t hpm_github_token_bytes(hpm_github_token_t* t, uint8_t* out, size_t cap);
void    hpm_github_token_free(hpm_github_token_t* t);
int     hpm_github_response_status_get(hpm_github_response_t* r);
ssize_t hpm_github_response_body_get(hpm_github_response_t* r, uint8_t* out, size_t cap);
void    hpm_github_response_free(hpm_github_response_t* r);
```

## Auth flow

The canonical GitHub App auth flow is two-step:

```
                    +----------------+
  app_id, pem  -->  | generate_jwt   |  -->  jwt (5–600 s)
                    +----------------+

                          +-------------------------+
  jwt, install_id   -->   | get_installation_token  |  -->  install_token (~60 min)
                          +-------------------------+

  install_token, ...  --> [any REST op]               -->  response
```

The install_token is what you pass to `post_pr_comment` / `create_check_run` /
etc. The JWT only gets used to mint install_tokens — never directly to
REST ops.

## Common request headers

All requests inject:
```
Accept: application/vnd.github+json
X-GitHub-Api-Version: 2022-11-28
User-Agent: hpm-github-api-rsr/0.1
Authorization: Bearer <token>
```

POST/PATCH requests with JSON bodies additionally inject:
```
Content-Type: application/json
```

## Lifetime model

* `hpm_github_token_t*` and `hpm_github_response_t*` are independent
  heap allocations. Free with their matching `*_free`.
* `hpm_github_response_t` owns a copy of the body bytes; safe to read
  via `body_get` until you free it.
* JWTs and install_tokens use the same wrapper type. You can return one
  from the other; the caller doesn't have to know which is which (they
  both go to `bytes` / `free`).

## Error model

NULL return ⇒ failure. Common causes:
* JWT: bad PEM, missing/invalid app_id
* Install-token: HTTP error, non-2xx status, JSON missing "token" field
* REST ops: HTTP error (note: non-2xx is NOT treated as error here —
  the response struct still returns the status code and body for the
  caller to interpret)

## Linking

This library `extern fn`-declares symbols from the three siblings.
At build time pass `-Dsibling-prefix=<path>` if the siblings aren't at
`../../../`:

```sh
zig build -Dsibling-prefix=/path/to/parent
```

At runtime, the siblings' `.so` files must be findable. Either install
them system-wide or set:

```sh
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:\
  ../hpm-crypto-rsr/ffi/zig/zig-out/lib:\
  ../hpm-http-client-rsr/ffi/zig/zig-out/lib:\
  ../hpm-json-rsr/ffi/zig/zig-out/lib
```
