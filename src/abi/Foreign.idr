-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
||| hpm-github-api-rsr — %foreign declarations binding into libhpm_github_api.so.
|||
||| Returned `AnyPtr`s are opaque heap handles; callers MUST eventually
||| free them via the matching `*_free` function. NULL returns indicate
||| failure (auth, HTTP, JSON, or alloc) — caller responsibility to
||| handle.

module HpmGithubApi.ABI.Foreign

import Data.Buffer
import HpmGithubApi.ABI.Types

%default total

--------------------------------------------------------------------------------
-- JWT generation
--------------------------------------------------------------------------------

%foreign "C:hpm_github_app_generate_jwt, libhpm_github_api"
prim__generateJwt : Buffer -> Int -> Buffer -> Int -> Int -> PrimIO AnyPtr

||| Generate a GitHub App JWT. `appId` is decimal-encoded.
||| `lifetimeSeconds` is clamped to 600s by the C side.
export
generateJwt :
  (appId : Buffer) -> (appIdLen : Int) ->
  (pem : Buffer) -> (pemLen : Int) ->
  (lifetimeSeconds : Int) ->
  IO AnyPtr
generateJwt aid alen pem plen life =
  primIO $ prim__generateJwt aid alen pem plen life

--------------------------------------------------------------------------------
-- Installation-token exchange
--------------------------------------------------------------------------------

%foreign "C:hpm_github_app_get_installation_token, libhpm_github_api"
prim__getInstallationToken : AnyPtr -> Int -> PrimIO AnyPtr

export
getInstallationToken : (jwt : AnyPtr) -> (installationId : Int) -> IO AnyPtr
getInstallationToken jwt iid =
  primIO $ prim__getInstallationToken jwt iid

--------------------------------------------------------------------------------
-- High-level operations
--------------------------------------------------------------------------------

%foreign "C:hpm_github_post_pr_comment, libhpm_github_api"
prim__postPRComment :
  AnyPtr -> Buffer -> Int -> Buffer -> Int -> Int -> Buffer -> Int -> PrimIO AnyPtr

export
postPRComment :
  (token : AnyPtr) ->
  (owner : Buffer) -> (ownerLen : Int) ->
  (repo : Buffer) -> (repoLen : Int) ->
  (issueNumber : Int) ->
  (body : Buffer) -> (bodyLen : Int) ->
  IO AnyPtr
postPRComment t o ol r rl n b bl =
  primIO $ prim__postPRComment t o ol r rl n b bl

%foreign "C:hpm_github_update_comment, libhpm_github_api"
prim__updateComment :
  AnyPtr -> Buffer -> Int -> Buffer -> Int -> Int -> Buffer -> Int -> PrimIO AnyPtr

export
updateComment :
  (token : AnyPtr) ->
  (owner : Buffer) -> (ownerLen : Int) ->
  (repo : Buffer) -> (repoLen : Int) ->
  (commentId : Int) ->
  (body : Buffer) -> (bodyLen : Int) ->
  IO AnyPtr
updateComment t o ol r rl cid b bl =
  primIO $ prim__updateComment t o ol r rl cid b bl

%foreign "C:hpm_github_create_check_run, libhpm_github_api"
prim__createCheckRun :
  AnyPtr ->
  Buffer -> Int -> Buffer -> Int ->
  Buffer -> Int -> Buffer -> Int ->
  Buffer -> Int -> Buffer -> Int ->
  PrimIO AnyPtr

export
createCheckRun :
  (token : AnyPtr) ->
  (owner : Buffer) -> (ownerLen : Int) ->
  (repo : Buffer) -> (repoLen : Int) ->
  (name : Buffer) -> (nameLen : Int) ->
  (headSha : Buffer) -> (headShaLen : Int) ->
  (status : Buffer) -> (statusLen : Int) ->
  (conclusion : Buffer) -> (conclusionLen : Int) ->
  IO AnyPtr
createCheckRun t o ol r rl n nl s sl st stl c cl =
  primIO $ prim__createCheckRun t o ol r rl n nl s sl st stl c cl

%foreign "C:hpm_github_get_pull_request, libhpm_github_api"
prim__getPullRequest : AnyPtr -> Buffer -> Int -> Buffer -> Int -> Int -> PrimIO AnyPtr

export
getPullRequest :
  (token : AnyPtr) ->
  (owner : Buffer) -> (ownerLen : Int) ->
  (repo : Buffer) -> (repoLen : Int) ->
  (prNumber : Int) ->
  IO AnyPtr
getPullRequest t o ol r rl n = primIO $ prim__getPullRequest t o ol r rl n

%foreign "C:hpm_github_get_repository, libhpm_github_api"
prim__getRepository : AnyPtr -> Buffer -> Int -> Buffer -> Int -> PrimIO AnyPtr

export
getRepository :
  (token : AnyPtr) ->
  (owner : Buffer) -> (ownerLen : Int) ->
  (repo : Buffer) -> (repoLen : Int) ->
  IO AnyPtr
getRepository t o ol r rl = primIO $ prim__getRepository t o ol r rl

--------------------------------------------------------------------------------
-- Accessors + lifecycle
--------------------------------------------------------------------------------

%foreign "C:hpm_github_token_bytes, libhpm_github_api"
prim__tokenBytes : AnyPtr -> Buffer -> Int -> PrimIO Int

export
tokenBytes : AnyPtr -> Buffer -> Int -> IO BytesResult
tokenBytes t out cap = do
  rc <- primIO $ prim__tokenBytes t out cap
  pure (bytesResultFromInt rc)

%foreign "C:hpm_github_token_free, libhpm_github_api"
prim__tokenFree : AnyPtr -> PrimIO ()

export
tokenFree : AnyPtr -> IO ()
tokenFree t = primIO $ prim__tokenFree t

%foreign "C:hpm_github_response_status_get, libhpm_github_api"
prim__responseStatus : AnyPtr -> PrimIO Int

export
responseStatus : AnyPtr -> IO HttpStatus
responseStatus r = do
  code <- primIO $ prim__responseStatus r
  pure (MkHttpStatus code)

%foreign "C:hpm_github_response_body_get, libhpm_github_api"
prim__responseBody : AnyPtr -> Buffer -> Int -> PrimIO Int

export
responseBody : AnyPtr -> Buffer -> Int -> IO BytesResult
responseBody r out cap = do
  rc <- primIO $ prim__responseBody r out cap
  pure (bytesResultFromInt rc)

%foreign "C:hpm_github_response_free, libhpm_github_api"
prim__responseFree : AnyPtr -> PrimIO ()

export
responseFree : AnyPtr -> IO ()
responseFree r = primIO $ prim__responseFree r
