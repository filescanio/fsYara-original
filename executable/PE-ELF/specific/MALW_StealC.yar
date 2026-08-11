rule StealC_v2_ABE_BrowserInjector {
  meta:
		hash = "3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6"
		score = 75
    author           = "yara-author agent"
    date             = "2026-08-11"
    description      = "Detects StealC v2 infostealer: CIS-locale victim exclusion, hand-rolled RC4 string decryptor, and the pe2shc-wrapped embedded PE used for Chrome/Brave/Edge App-Bound-Encryption (ABE) key theft via Early Bird APC injection"
    family           = "StealC v2"
    category         = "infostealer"
    confidence       = "medium-high"
    reference_sha256 = "3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6"
    hash_md5         = "5e21d4f7b0f651bb8ec310da7c213f25"

  strings:
    // Gold opcode 1: CIS-locale suicide chain from WinMain (0x14002B938).
    // movzx ecx, ax (GetUserDefaultLangID) then a differential subtract
    // chain testing 0x419 (ru-RU), +9=0x422 (uk-UA), +1=0x423 (be-BY),
    // +0x1C=0x43F (kk-KZ), +4=0x443 (uz-UZ); any match falls through to
    // xor ecx,ecx / call ExitProcess. Only jump displacements wildcarded.
    $op_locale_suicide = {
      0F B7 C8 81 E9 19 04 00 00 74 ?? 83 E9 09 74 ??
      83 E9 01 74 ?? 83 E9 1C 74 ?? 83 F9 04 75 ?? 33 C9 FF 15 ?? ?? ?? ??
    }

    // Gold opcode 2: RC4 key-scheduling (KSA) swap loop from the
    // hand-rolled RC4 implementation at 0x1400256B0 (addr 0x140025742).
    // movzx from key-schedule T[] and state S[], j += S[i] + T[i],
    // signed-modulo-256 idiom (and r8d,800000FFh / jge / dec /
    // or r8d,0FFFFFF00h / inc), then the two-way S[i]<->S[j] swap.
    // Zero relocations; only one jump displacement is wildcarded.
    $op_rc4_ksa_swap = {
      41 0F B6 0C 01 43 0F B6 1C 11 44 03 C1 44 03 C3
      41 81 E0 FF 00 00 80 7D ?? 41 FF C8 41 81 C8 00 FF FF FF
      41 FF C0 49 63 C8 42 8A 04 11 43 88 04 11 41 FF C1 42 88 1C 11
    }

    // Gold opcode 3: RC4 PRGA keystream XOR from the same routine
    // (addr 0x1400257F2). Computes S[(S[i]+S[j]) & 0xFF] and XORs it
    // with the ciphertext byte: movzx both state bytes, add, truncate
    // to 8 bits, index S, xor cl,[rdx+r15]. Fully literal, no wildcards.
    $op_rc4_keystream_xor = {
      42 0F B6 0C 09 43 0F B6 04 08 48 03 C8 0F B6 C1
      42 8A 0C 08 42 32 0C 3A
    }

    // Gold opcode 4 (technique-shared, kept only as corroborating
    // evidence, never sufficient alone): pe2shc-style reflective-loader
    // stub prepended to the embedded ABE-theft PE at 0x140092D20.
    // 'MZER' fake DOS magic, call $+5 / pop rcx / sub rcx,9 recovers the
    // blob base, add rax,<SizeOfImage> jumps into the appended loader,
    // ret. SizeOfImage immediate wildcarded since it varies per build.
    $op_mzer_pe2shc_stub = {
      4D 5A 45 52 E8 00 00 00 00 59 48 83 E9 09 48 8B C1
      48 05 ?? ?? ?? ?? FF D0 C3
    }

    // Silver string: JSON key the injected module searches for in
    // Chrome/Brave/Edge "Local State" before calling IElevator::DecryptData.
    // Plaintext inside the embedded payload (not RC4-encrypted like the
    // outer stealer's own strings).
    $str_abe_key_marker = "\"app_bound_encrypted_key\":\""

    // Silver strings: relative Local State paths for the three targeted
    // Chromium browsers, plaintext ANSI inside the embedded ABE payload.
    $str_localstate_chrome = "\\Google\\Chrome\\User Data\\Local State"
    $str_localstate_brave  = "\\BraveSoftware\\Brave-Browser\\User Data\\Local State"
    $str_localstate_edge   = "\\Microsoft\\Edge\\User Data\\Local State"

  condition:
    uint16(0) == 0x5A4D
    and filesize > 300KB and filesize < 2MB
    and (
      // Two independent, near-zero-wildcard gold opcode families
      // (locale-exclusion behaviour + custom RC4 crypto) is already
      // a strong family-level signal on its own.
      2 of ($op_locale_suicide, $op_rc4_ksa_swap, $op_rc4_keystream_xor)
      or
      // Otherwise require the pe2shc stub (technique-shared) plus at
      // least two of the ABE-specific plaintext strings that live
      // only inside the embedded browser-injection payload, tying
      // the injected blob to the Chrome/Brave/Edge ABE key theft.
      (
        $op_mzer_pe2shc_stub
        and 2 of ($str_abe_key_marker, $str_localstate_chrome, $str_localstate_brave, $str_localstate_edge)
      )
    )
}
