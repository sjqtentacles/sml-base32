(* base32.sig

   Base32 codecs in pure Standard ML, covering the four widely used
   alphabets. All encoders treat the input as an opaque byte string (a
   `string` of 8-bit `char`s) and produce 7-bit ASCII output; all decoders
   return `NONE` on malformed input rather than raising.

     - RFC 4648 standard Base32  (alphabet A-Z 2-7, '=' padding)
     - RFC 4648 base32hex        (alphabet 0-9 A-V, '=' padding)
     - Crockford Base32          (excludes I L O U; no padding; case-
                                  insensitive decode mapping I/L -> 1, O -> 0;
                                  '-' separators are ignored on decode)
     - z-base-32                 (alphabet ybndrfg8ejkmcpqxot1uwisza345h769;
                                  lowercase, no padding)

   Standard and base32hex decoding is case-insensitive. Round-trip holds for
   every variant: `decodeX (encodeX s) = SOME s`. *)

signature BASE32 =
sig
  (* RFC 4648 standard Base32. *)
  val encode : string -> string
  val decode : string -> string option

  (* RFC 4648 base32hex (extended-hex alphabet). *)
  val encodeHex : string -> string
  val decodeHex : string -> string option

  (* Crockford Base32. *)
  val encodeCrockford : string -> string
  val decodeCrockford : string -> string option

  (* z-base-32. *)
  val encodeZ : string -> string
  val decodeZ : string -> string option
end
