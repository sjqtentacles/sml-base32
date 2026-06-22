(* demo.sml - encode a sample string in every Base32 variant, then decode the
   standard form back to prove the round-trip. *)

fun showOpt NONE = "NONE"
  | showOpt (SOME s) = "SOME \"" ^ s ^ "\""

val sample = "foobar"

val () =
  ( print ("input                  = \"" ^ sample ^ "\"\n")
  ; print ("encode (RFC 4648)      = " ^ Base32.encode sample ^ "\n")
  ; print ("encodeHex (base32hex)  = " ^ Base32.encodeHex sample ^ "\n")
  ; print ("encodeCrockford        = " ^ Base32.encodeCrockford sample ^ "\n")
  ; print ("encodeZ (z-base-32)    = " ^ Base32.encodeZ sample ^ "\n")
  ; print ("decode (RFC 4648)      = " ^ showOpt (Base32.decode (Base32.encode sample)) ^ "\n")
  ; print ("decode lowercase       = " ^ showOpt (Base32.decode "mzxw6ytboi======") ^ "\n")
  ; print ("decodeCrockford I->1   = " ^ showOpt (Base32.decodeCrockford "CSQPYRKIE8") ^ "\n")
  )
