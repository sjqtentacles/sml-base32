# sml-base32

[![CI](https://github.com/sjqtentacles/sml-base32/actions/workflows/ci.yml/badge.svg)](https://github.com/sjqtentacles/sml-base32/actions/workflows/ci.yml)

Base32 codecs in pure Standard ML — RFC 4648 standard, RFC 4648 base32hex,
Crockford Base32, and z-base-32.

Base32 packs an arbitrary byte string into a 32-character, case-insensitive,
typo-resistant alphabet — handy for human-keyed secrets (TOTP keys), URLs, and
file names. This library is a single, self-contained `Base32` structure over
the Basis library, with no dependencies, no FFI, no threads, and no clock —
same bytes in, same bytes out, every time. The bit packing uses a small
streaming accumulator that never holds more than 12 bits, so output is
byte-for-byte identical under **MLton** (32-bit default `int`) and **Poly/ML**
(63-bit `int`).

Verified against the **RFC 4648 test vectors** on both compilers.

## API

```sml
structure Base32 : sig
  (* RFC 4648 standard Base32 (alphabet A-Z 2-7, '=' padding) *)
  val encode          : string -> string
  val decode          : string -> string option

  (* RFC 4648 base32hex (alphabet 0-9 A-V, '=' padding) *)
  val encodeHex       : string -> string
  val decodeHex       : string -> string option

  (* Crockford Base32 (excludes I L O U; no padding; case-insensitive
     decode mapping I/L -> 1 and O -> 0; '-' separators ignored) *)
  val encodeCrockford : string -> string
  val decodeCrockford : string -> string option

  (* z-base-32 (alphabet ybndrfg8ejkmcpqxot1uwisza345h769; no padding) *)
  val encodeZ         : string -> string
  val decodeZ         : string -> string option
end
```

Encoders treat the input as an opaque byte string (a `string` of 8-bit
`char`s) and produce 7-bit ASCII. Decoders return `NONE` on malformed input
(unknown characters, non-canonical lengths, misplaced padding) instead of
raising. Standard and base32hex decoding is case-insensitive. Round-trip holds
for every variant: `decodeX (encodeX s) = SOME s`.

### Example

```sml
val () = print (Base32.encode "foobar" ^ "\n")          (* MZXW6YTBOI====== *)
val () = print (Base32.encodeHex "foobar" ^ "\n")       (* CPNMUOJ1E8====== *)
val () = print (Base32.encodeCrockford "foobar" ^ "\n") (* CSQPYRK1E8 *)
val () = print (Base32.encodeZ "foobar" ^ "\n")         (* c3zs6aubqe *)

(* decode is case-insensitive; Crockford maps I/L -> 1, O -> 0 *)
val SOME s = Base32.decode "mzxw6ytboi======"           (* "foobar" *)
val SOME k = Base32.decodeCrockford "CSQPYRKIE8"        (* "foobar" (I read as 1) *)
```

Running [`examples/demo.sml`](examples/demo.sml) with `make example` prints:

```
input                  = "foobar"
encode (RFC 4648)      = MZXW6YTBOI======
encodeHex (base32hex)  = CPNMUOJ1E8======
encodeCrockford        = CSQPYRK1E8
encodeZ (z-base-32)    = c3zs6aubqe
decode (RFC 4648)      = SOME "foobar"
decode lowercase       = SOME "foobar"
decodeCrockford I->1   = SOME "foobar"
```

## Build & test

Requires [MLton](http://mlton.org/) and/or [Poly/ML](https://polyml.org/).

```sh
make test        # build + run the suite under MLton
make test-poly   # run the suite under Poly/ML
make all-tests   # both
make example     # build + run the demo
make clean
```

## Installing with smlpkg

```sh
smlpkg add github.com/sjqtentacles/sml-base32
smlpkg sync
```

Reference `lib/github.com/sjqtentacles/sml-base32/base32.mlb` from your own
`.mlb` (MLton / MLKit), or feed `sources.mlb` to `tools/polybuild` (Poly/ML).

## Layout

```
sml.pkg                                       smlpkg manifest
Makefile                                      MLton + Poly/ML targets
.github/workflows/ci.yml                      CI: MLton + Poly/ML
lib/github.com/sjqtentacles/sml-base32/
  base32.sig     BASE32 signature
  base32.sml     codec implementation (streaming bit buffer)
  sources.mlb    ordered source list
  base32.mlb     public basis
examples/
  demo.sml       encodes a sample in all four variants + decodes
test/
  harness.sml    shared assertion harness
  test.sml       RFC 4648 vectors + variant + fuzz suite (51 checks)
  entry.sml / main.sml
tools/polybuild  Poly/ML build wrapper
```

## Tests

51 deterministic checks: the **RFC 4648 §10 test vectors** for both the
standard alphabet (`""`, `"f"`→`MY======`, … `"foobar"`→`MZXW6YTBOI======`)
and base32hex (`"foobar"`→`CPNMUOJ1E8======`), case-insensitive decoding,
malformed-input rejection, Crockford encoding (no `I`/`L`/`O`/`U`) with
case-insensitive `I`/`L`→`1`, `O`→`0` decoding and `-` separator tolerance,
z-base-32 vectors, and round-trip fuzzing over byte strings of length 0–64 for
all four variants. Run `make all-tests` to verify identical output under both
compilers.

## License

MIT. See [LICENSE](LICENSE).
