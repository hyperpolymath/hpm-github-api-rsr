||| hpm-github-api-rsr — type declarations for the FFI boundary.

module HpmGithubApi.ABI.Types

import Data.Buffer

%default total

--------------------------------------------------------------------------------
-- Size / read results
--------------------------------------------------------------------------------

||| Outcome of a `bytes`/`body` read. The C side returns:
|||   ≥ 0  = bytes written (or required size if `cap == 0`)
|||   -1   = error (cap < required / null)
public export
data BytesResult : Type where
  BytesOk : (bytesWritten : Nat) -> BytesResult
  BytesError : BytesResult

export
bytesResultFromInt : Int -> BytesResult
bytesResultFromInt n =
  if n < 0
    then BytesError
    else BytesOk (cast n)

--------------------------------------------------------------------------------
-- HTTP status
--------------------------------------------------------------------------------

public export
record HttpStatus where
  constructor MkHttpStatus
  code : Int

export
isSuccess : HttpStatus -> Bool
isSuccess s = s.code >= 200 && s.code < 300
