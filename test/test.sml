structure Tests =
struct

  (* Deterministic pseudo-random byte string (small overflow-safe LCG) for
     round-trip fuzzing - constants stay well within 32-bit int. *)
  fun lcg seed = (seed * 75 + 74) mod 65537
  fun randStr (seed, len) =
    let
      fun go (_, 0, acc) = String.implode (List.rev acc)
        | go (s, k, acc) =
            let val s' = lcg s
            in go (s', k - 1, Char.chr (s' mod 256) :: acc) end
    in
      go (seed, len, [])
    end

  fun roundTrips (enc, dec) s = (dec (enc s) = SOME s)

  (* Round-trips every byte string of length 0..maxLen, distinct seed per
     length, across one codec. Returns true iff all succeed. *)
  fun fuzzOk codec maxLen =
    List.all
      (fn n => roundTrips codec (randStr (n * 101 + 17, n)))
      (List.tabulate (maxLen + 1, fn i => i))

  fun runAll () =
    let
      (* ---- RFC 4648 standard Base32 vectors (Section 10) ---- *)
      val () = Harness.section "RFC 4648 standard Base32 encode"
      val () = Harness.checkString "encode \"\""        ("",                 Base32.encode "")
      val () = Harness.checkString "encode \"f\""       ("MY======",         Base32.encode "f")
      val () = Harness.checkString "encode \"fo\""      ("MZXQ====",         Base32.encode "fo")
      val () = Harness.checkString "encode \"foo\""     ("MZXW6===",         Base32.encode "foo")
      val () = Harness.checkString "encode \"foob\""    ("MZXW6YQ=",         Base32.encode "foob")
      val () = Harness.checkString "encode \"fooba\""   ("MZXW6YTB",         Base32.encode "fooba")
      val () = Harness.checkString "encode \"foobar\""  ("MZXW6YTBOI======", Base32.encode "foobar")

      val () = Harness.section "RFC 4648 standard Base32 decode"
      val () = Harness.check "decode \"\""        (Base32.decode ""                 = SOME "")
      val () = Harness.check "decode \"MY======\""(Base32.decode "MY======"         = SOME "f")
      val () = Harness.check "decode \"MZXQ====\""(Base32.decode "MZXQ===="         = SOME "fo")
      val () = Harness.check "decode \"MZXW6===\""(Base32.decode "MZXW6==="         = SOME "foo")
      val () = Harness.check "decode \"MZXW6YQ=\""(Base32.decode "MZXW6YQ="         = SOME "foob")
      val () = Harness.check "decode \"MZXW6YTB\""(Base32.decode "MZXW6YTB"         = SOME "fooba")
      val () = Harness.check "decode \"MZXW6YTBOI======\""
                 (Base32.decode "MZXW6YTBOI======" = SOME "foobar")
      (* decode is case-insensitive for the standard alphabet *)
      val () = Harness.check "decode lowercase \"my======\""
                 (Base32.decode "my======" = SOME "f")
      val () = Harness.check "decode lowercase \"mzxw6ytboi======\""
                 (Base32.decode "mzxw6ytboi======" = SOME "foobar")

      (* ---- Standard Base32 rejects malformed input ---- *)
      val () = Harness.section "Standard Base32 rejects malformed input"
      val () = Harness.check "reject single char (1 mod 8)"  (Base32.decode "A" = NONE)
      val () = Harness.check "reject 3 data chars (3 mod 8)"  (Base32.decode "MZX" = NONE)
      val () = Harness.check "reject char outside alphabet '1'" (Base32.decode "1" = NONE)
      val () = Harness.check "reject char outside alphabet '8'" (Base32.decode "8" = NONE)
      val () = Harness.check "reject leading pad"             (Base32.decode "=MY=====" = NONE)
      val () = Harness.check "reject data after pad"          (Base32.decode "MY=A====" = NONE)

      (* ---- RFC 4648 base32hex vectors (Section 10) ---- *)
      val () = Harness.section "RFC 4648 base32hex encode"
      val () = Harness.checkString "encodeHex \"\""       ("",                 Base32.encodeHex "")
      val () = Harness.checkString "encodeHex \"f\""      ("CO======",         Base32.encodeHex "f")
      val () = Harness.checkString "encodeHex \"fo\""     ("CPNG====",         Base32.encodeHex "fo")
      val () = Harness.checkString "encodeHex \"foo\""    ("CPNMU===",         Base32.encodeHex "foo")
      val () = Harness.checkString "encodeHex \"foob\""   ("CPNMUOG=",         Base32.encodeHex "foob")
      val () = Harness.checkString "encodeHex \"fooba\""  ("CPNMUOJ1",         Base32.encodeHex "fooba")
      val () = Harness.checkString "encodeHex \"foobar\"" ("CPNMUOJ1E8======", Base32.encodeHex "foobar")

      val () = Harness.section "RFC 4648 base32hex decode"
      val () = Harness.check "decodeHex \"CO======\""  (Base32.decodeHex "CO======" = SOME "f")
      val () = Harness.check "decodeHex \"CPNMUOJ1E8======\""
                 (Base32.decodeHex "CPNMUOJ1E8======" = SOME "foobar")
      val () = Harness.check "decodeHex lowercase"
                 (Base32.decodeHex "cpnmuoj1e8======" = SOME "foobar")
      (* base32hex and standard alphabets are distinct: cross-decode must differ *)
      val () = Harness.check "base32hex \"MY\" is not standard \"f\""
                 (Base32.decodeHex "MY======" <> SOME "f")

      (* ---- Crockford Base32 ---- *)
      val () = Harness.section "Crockford Base32 encode"
      val () = Harness.checkString "encodeCrockford \"\""       ("",           Base32.encodeCrockford "")
      val () = Harness.checkString "encodeCrockford \"f\""      ("CR",         Base32.encodeCrockford "f")
      val () = Harness.checkString "encodeCrockford \"foobar\"" ("CSQPYRK1E8", Base32.encodeCrockford "foobar")
      (* Crockford alphabet excludes I, L, O, U entirely *)
      val () = Harness.check "Crockford output omits I/L/O/U"
                 (List.all
                    (fn s =>
                       not (List.exists
                              (fn c => Char.contains "ILOU" c)
                              (String.explode (Base32.encodeCrockford s))))
                    [ "f", "fo", "foo", "foob", "fooba", "foobar"
                    , "\000\001\002\003\004", "hello world", "\255\254\253" ])

      val () = Harness.section "Crockford Base32 decode"
      val () = Harness.check "decodeCrockford \"CR\""         (Base32.decodeCrockford "CR" = SOME "f")
      val () = Harness.check "decodeCrockford \"CSQPYRK1E8\"" (Base32.decodeCrockford "CSQPYRK1E8" = SOME "foobar")
      (* case-insensitive *)
      val () = Harness.check "decodeCrockford lowercase"
                 (Base32.decodeCrockford "csqpyrk1e8" = SOME "foobar")
      (* ambiguity mapping: I and L decode as 1, O decodes as 0 *)
      val () = Harness.check "decodeCrockford I == 1"
                 (Base32.decodeCrockford "CSQPYRKIE8" = SOME "foobar")
      val () = Harness.check "decodeCrockford L == 1"
                 (Base32.decodeCrockford "CSQPYRKLE8" = SOME "foobar")
      val () = Harness.check "decodeCrockford O == 0"
                 (Base32.decodeCrockford "OO" = Base32.decodeCrockford "00")
      (* '-' separators are ignored on decode *)
      val () = Harness.check "decodeCrockford ignores '-'"
                 (Base32.decodeCrockford "CSQP-YRK1-E8" = SOME "foobar")

      (* ---- z-base-32 ---- *)
      val () = Harness.section "z-base-32"
      val () = Harness.checkString "encodeZ \"\""       ("",           Base32.encodeZ "")
      val () = Harness.checkString "encodeZ \"foobar\"" ("c3zs6aubqe", Base32.encodeZ "foobar")
      val () = Harness.check "decodeZ \"c3zs6aubqe\""   (Base32.decodeZ "c3zs6aubqe" = SOME "foobar")

      (* ---- Round-trip fuzz across all four variants ---- *)
      val () = Harness.section "Round-trip fuzz (lengths 0..64)"
      val () = Harness.check "standard round-trips"   (fuzzOk (Base32.encode,          Base32.decode)          64)
      val () = Harness.check "base32hex round-trips"  (fuzzOk (Base32.encodeHex,       Base32.decodeHex)       64)
      val () = Harness.check "crockford round-trips"  (fuzzOk (Base32.encodeCrockford, Base32.decodeCrockford) 64)
      val () = Harness.check "z-base-32 round-trips"  (fuzzOk (Base32.encodeZ,         Base32.decodeZ)         64)
    in
      Harness.run ()
    end

  val run = runAll
end
