(* base32.sml

   Base32 codecs (RFC 4648 standard + base32hex, Crockford, z-base-32).

   The bit packing is done with a tiny streaming accumulator that never holds
   more than 12 bits, so every intermediate value stays a small machine int.
   This keeps the code byte-identical across MLton (32-bit default int) and
   Poly/ML (63-bit int) with no reliance on word/int widths. *)

structure Base32 :> BASE32 =
struct

  (* ---- alphabets (index = 5-bit value) ---- *)
  val stdAlpha   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  val hexAlpha   = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
  val crockAlpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
  val zAlpha     = "ybndrfg8ejkmcpqxot1uwisza345h769"

  fun pow2 e = if e <= 0 then 1 else 2 * pow2 (e - 1)

  (* ---- encoding ----

     Stream input bytes through a bit buffer, emitting one alphabet character
     for every 5 bits. A trailing partial group is left-padded with zero bits;
     when [padTo8] is true the output is padded with '=' up to a multiple of 8
     characters (RFC 4648 standard / base32hex). *)
  fun encodeGeneric (alpha, padTo8) input =
    let
      val n = String.size input
      fun chr5 v = String.sub (alpha, v)

      (* (i, buffer, bits, acc) -> reversed char list *)
      fun loop (i, buf, bits, acc) =
        if bits >= 5 then
          let
            val bits' = bits - 5
            val v = (buf div pow2 bits') mod 32
          in
            loop (i, buf mod pow2 bits', bits', chr5 v :: acc)
          end
        else if i < n then
          let val b = Char.ord (String.sub (input, i))
          in loop (i + 1, buf * 256 + b, bits + 8, acc) end
        else if bits > 0 then
          (* flush final partial group, left-padded with zero bits *)
          let val v = (buf * pow2 (5 - bits)) mod 32
          in List.rev (chr5 v :: acc) end
        else
          List.rev acc

      val chars = loop (0, 0, 0, [])
      val body = String.implode chars
    in
      if not padTo8 then body
      else
        let val r = String.size body mod 8
        in if r = 0 then body
           else body ^ String.implode (List.tabulate (8 - r, fn _ => #"="))
        end
    end

  fun encode s          = encodeGeneric (stdAlpha,   true)  s
  fun encodeHex s       = encodeGeneric (hexAlpha,   true)  s
  fun encodeCrockford s = encodeGeneric (crockAlpha, false) s
  fun encodeZ s         = encodeGeneric (zAlpha,     false) s

  (* ---- decoding ---- *)

  (* Reverse lookup table over 7-bit ASCII; ~1 marks "not in alphabet". *)
  fun mkTable alpha =
    let
      val arr = Array.array (128, ~1)
      fun fill i =
        if i >= String.size alpha then ()
        else ( Array.update (arr, Char.ord (String.sub (alpha, i)), i)
             ; fill (i + 1) )
      val () = fill 0
    in
      fn c =>
        let val k = Char.ord c
        in if k >= 0 andalso k < 128
           then let val v = Array.sub (arr, k)
                in if v < 0 then NONE else SOME v end
           else NONE
        end
    end

  val stdVal   = mkTable stdAlpha
  val hexVal   = mkTable hexAlpha
  val crockVal = mkTable crockAlpha
  val zVal     = mkTable zAlpha

  fun upper s = String.map Char.toUpper s
  fun lower s = String.map Char.toLower s

  (* Crockford decode normalisation: uppercase, drop '-' separators, map the
     ambiguous letters I/L -> 1 and O -> 0. *)
  fun prepCrock s =
    String.translate
      (fn c =>
         case Char.toUpper c of
           #"-" => ""
         | #"I" => "1"
         | #"L" => "1"
         | #"O" => "0"
         | c'   => String.str c')
      s

  (* Core decoder: [value] maps a (preprocessed) character to its 5-bit value
     or NONE. Trailing '=' is accepted only as canonical padding. *)
  fun decodeGeneric value input =
    let
      val n = String.size input

      (* split the data region (before first '=') from the padding region *)
      fun firstPad i =
        if i >= n then n
        else if String.sub (input, i) = #"=" then i
        else firstPad (i + 1)
      val dataEnd = firstPad 0

      fun allPad i =
        i >= n orelse (String.sub (input, i) = #"=" andalso allPad (i + 1))

      (* stream 5-bit values through a bit buffer, emitting one byte per 8 bits *)
      fun loop (i, buf, bits, acc) =
        if bits >= 8 then
          let
            val bits' = bits - 8
            val b = (buf div pow2 bits') mod 256
          in
            loop (i, buf mod pow2 bits', bits', Char.chr b :: acc)
          end
        else if i >= dataEnd then
          SOME (List.rev acc)
        else
          case value (String.sub (input, i)) of
            NONE => NONE
          | SOME v => loop (i + 1, buf * 32 + v, bits + 5, acc)

      val ndata = dataEnd
      val r = ndata mod 8
    in
      (* reject non-canonical data lengths (1, 3, 6 chars never occur) and any
         non-'=' character in the padding region *)
      if not (allPad dataEnd) then NONE
      else if r = 1 orelse r = 3 orelse r = 6 then NONE
      else case loop (0, 0, 0, []) of
             NONE => NONE
           | SOME bytes => SOME (String.implode bytes)
    end

  fun decode s          = decodeGeneric stdVal   (upper s)
  fun decodeHex s       = decodeGeneric hexVal   (upper s)
  fun decodeCrockford s = decodeGeneric crockVal (prepCrock s)
  fun decodeZ s         = decodeGeneric zVal     (lower s)
end
