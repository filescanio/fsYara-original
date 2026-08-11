import "pe"

rule Stealer_VidarStealC_Lineage_CIS_ABE_Injector {
  meta:
		hash = "3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6"
		score = 75
    author                      = "agentic-yara"
    date                        = "2026-08-11"
    description                 = "Detects a modern MSVC C++ infostealer/loader (Vidar/StealC lineage, family unconfirmed) via its CIS-locale exclusion ladder, embedded 'MZER' App-Bound-Encryption bypass module, RC4 string-config decryptor, task dispatcher, and the family's 'soft\\<App>\\' exfil archive layout. Config strings are base64+RC4 encrypted in .rdata and decrypted at startup."
    malware_category            = "infostealer, loader"
    malware_family              = "unconfirmed (Vidar/StealC v2 lineage)"
    confidence                  = "high"
    reference_sha256            = "3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6"
    sample_unique_iocs_not_used = "RC4 key jG6l0Thtpyy5HfbvqH, network key oYiRntr1xvJFxHjBU, C2 http://135.181.127.244, kill-date 30/08/2026 - per-build only, excluded from this rule"

  strings:
    // --- gold opcode patterns (each verified unique, address-independent) ---

    // movzx ecx,ax ; sub ecx,419h(1049 ru-RU) ; jz exit ; sub ecx,9(1058 uk-UA) ; jz exit ;
    // sub ecx,1(1059 be-BY) ; jz exit ; sub ecx,1Ch(1087 kk-KZ) ; jz exit ; cmp ecx,4(1091 uz-UZ) ;
    // jnz skip ; xor ecx,ecx ; call [ExitProcess]. CIS-locale kill switch on GetUserDefaultLangID result.
    $op_cis = { 0F B7 C8 81 E9 19 04 00 00 74 ?? 83 E9 09 74 ?? 83 E9 01 74 ?? 83 E9 1C 74 ?? 83 F9 04 75 ?? 33 C9 FF 15 }

    // Custom 'MZER' DOS-magic header immediately followed by a self-relocating exec stub:
    // call $+5 ; pop rcx ; sub rcx,9 ; mov rax,rcx ; add rax,28000h ; call rax ; ret.
    // Anchors the embedded Chrome/Brave/Edge App-Bound-Encryption bypass PE carried in .data.
    $op_mzer = { 4D 5A 45 52 E8 00 00 00 00 59 48 83 E9 09 48 8B C1 48 05 00 80 02 00 FF D0 C3 }

    // mov esi,28600h (165376, size of the embedded MZER PE) ; mov r8d,esi ; mov [rsp+20h],40h
    // (PAGE_EXECUTE_READWRITE) ; mov r9d,3000h (MEM_COMMIT|MEM_RESERVE) ; xor edx,edx ; call [VirtualAllocEx].
    // RWX remote allocation sized exactly to the embedded payload, used by the injector.
    $op_rwx = { BE 00 86 02 00 44 8B C6 C7 44 24 20 40 00 00 00 41 B9 00 30 00 00 33 D2 FF 15 }

    // RC4 PRGA body of the shared string/config decryptor: movsxd r8,ebx ; movzx r9d,byte [r8+rdx] ;
    // add edi,r9d ; and edi,800000FFh ; jge L ; dec edi ; or edi,0FFFFFF00h ; inc edi ; movsxd rcx,edi ;
    // then swap S[i]/S[j]. The and/or pair is MSVC's idiom for signed "% 256", making this far more
    // specific than a generic RC4 implementation.
    $op_rc4 = { 4C 63 C3 45 0F B6 0C 10 41 03 F9 81 E7 FF 00 00 80 7D 0A FF CF 81 CF 00 FF FF FF FF C7 48 63 CF 8A 04 11 41 88 04 10 44 88 0C 11 }

    // --- silver opcode pattern (used as a supporting signal only) ---

    // mov ecx,[rbx+40h] (task-type field at record offset +64) ; sub ecx,1 ; jz ; sub ecx,1 ; jz ;
    // cmp ecx,1 ; jnz - dispatch ladder for C2 task IDs 1/2/3 (EXE / PowerShell / MSI). Record
    // stride is 112 bytes. Structurally distinctive but shorter/more generic than the gold patterns.
    $op_task = { 8B 4B 40 83 E9 01 74 ?? 83 E9 01 74 ?? 83 F9 01 75 }

    // --- gold string: typo'd PowerShell download cradle used for task type 2 ---
    $s_iwr_cradle = "iwr -UseBasicParsin" ascii

    // --- silver strings: family exfil-archive layout "soft\<App>\..." (require 3 of 4) ---
    $b_soft_steam   = "soft\\Steam\\tokens\\steam_tokens.txt" ascii
    $b_soft_winscp  = "soft\\WinSCP\\winscp.txt" ascii
    $b_soft_outlook = "soft\\Outlook\\outlook.txt" ascii
    $b_soft_foxmail = "soft\\FoxMail\\" ascii

  condition:
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    (
      2 of ($op_cis, $op_mzer, $op_rwx, $op_rc4, $op_task) or
      ($op_rc4 and $s_iwr_cradle)
    ) and
    (
      3 of ($b_soft_steam, $b_soft_winscp, $b_soft_outlook, $b_soft_foxmail) or
      $s_iwr_cradle
    )
}
