import "pe"

rule StealC_v2_Derivative_RC4_StringPool {
  meta:
		hash = "3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6"
		score = 75
    author         = "agentic-yara"
    description    = "StealC v2 family / close derivative: RC4 string-pool decoder with DIV-based key scheduling, WinSCP password codec, and OPSEC-slip plaintext config keys"
    malware_family = "StealC v2 (or close derivative)"
    category       = "Stealer"
    reference      = "IDA analysis .runtime/current/analysis/ida.json"
    tlp            = "amber"

  strings:
    // --- Opcode patterns (address-independent, each find_bytes-validated to exactly 1 match) ---

    // Shared string-deobfuscation wrapper (~269 callers): saves out-string, calls the
    // custom base64 decoder, then RC4-decrypts using the global key. Displacements for
    // both calls and the key lea are wildcarded so this survives rebasing.
    $op_decoder_wrapper = { 40 53 48 83 EC 60 48 8B D9 48 8D 4C 24 38 E8 ?? ?? ?? ?? 4C 8D 44 24 38 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 20 E8 }

    // RC4 key-schedule (KSA) inner body: instead of key[i % keylen] via AND mask, this
    // build zeroes rdx and issues a full 64-bit DIV against the std::string size field
    // ([rbx+10h]) on every one of the 256 iterations before storing the key byte.
    $op_rc4_ksa_div = { 33 D2 49 8B C2 48 F7 73 10 48 8B 45 E0 8A 0C 11 41 88 0C 01 41 FF C1 44 3B CF 7C CA }

    // RC4 output step (PRGA): movzx S[j]/S[i], add, truncate to byte, index the S-box
    // again, then XOR the keystream byte against the ciphertext cursor. Exact register
    // allocation (r8/r9/r15) is family-specific rather than generic textbook RC4.
    $op_rc4_prga_xor = { 42 0F B6 0C 09 43 0F B6 04 08 48 03 C8 0F B6 C1 42 8A 0C 08 42 32 0C 3A }

    // WinSCP password codec: rebuild the byte from two hex-nibble StrChrA lookups, then
    // "xor esi, 5Ch" - the algebraic fold of WinSCP's documented ~(x ^ 0xA3). Distinguishes
    // this implementation from stock WinSCP tooling, which uses 0xA3 plus a NOT instead.
    $op_winscp_xor_5c = { 45 2B F7 C1 E6 04 41 03 F6 83 F6 5C 40 0F B6 C6 }

    // --- Plaintext strings validated in code by the IDA pass ---

    // Config JSON keys left as plaintext literals while every sibling key in the same
    // parser (0x140027488) is base64+RC4 encrypted - an OPSEC slip unique to this build lineage.
    $str_steal_foxmail = "steal_foxmail" ascii
    $str_steal_winscp  = "steal_winscp" ascii

    // Malformed PowerShell download-and-execute command fragments concatenated at the
    // loader routine: note the leading quote, truncated "UseBasicParsin" (missing the g),
    // and trailing space/close-quote - not a generic PowerShell string.
    $str_iwr_prefix = "\"iwr -UseBasicParsin " ascii
    $str_iex_suffix = " |iex\"" ascii

    // Non-standard 36-char shuffled alphabet used for random name/ID generation; not a
    // standard base62/base36 set and not produced by any CRT routine.
    $str_alphabet = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ" ascii

  condition:
    uint16(0) == 0x5A4D
    and pe.machine == pe.MACHINE_AMD64
    and filesize < 5MB
    // Core detection: the shared decoder plus at least one of the two distinctive RC4
    // sub-routines is sufficient on its own, since every string in the binary flows
    // through this pipeline.
    and (
      $op_decoder_wrapper and (1 of ($op_rc4_ksa_div, $op_rc4_prga_xor))
    )
    // Corroborating evidence from at least one independent family-specific mechanism,
    // to push past a single build-specific RC4 routine into a firmer family match.
    and (
      $op_winscp_xor_5c
      or all of ($str_steal_foxmail, $str_steal_winscp)
      or all of ($str_iwr_prefix, $str_iex_suffix)
      or $str_alphabet
    )
}
