rule Stealc
{
    meta:
        author = "kevoreilly"
        description = "Stealc Payload"
        cape_type = "Stealc Payload"
        hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
    strings:
        $nugget1 = {68 04 01 00 00 6A 00 FF 15 [4] 50 FF 15}
        $nugget2 = {64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 89 45 FC}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule StealcAnti
{
    meta:
        author = "kevoreilly"
        description = "Stealc detonation bypass"
        cape_options = "bp0=$anti+17,action0=skip,count=1"
        hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
    strings:
        $anti = {53 57 57 57 FF 15 [4] 8B F0 74 03 75 01 B8 E8 [4] 74 03 75 01 B8}
        $decode = {6A 03 33 D2 8B F8 59 F7 F1 8B C7 85 D2 74 04 2B C2 03 C1 6A 06 C1 E0 03 33 D2 59 F7 F1}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule StealcStrings
{
    meta:
        author = "kevoreilly"
        description = "Stealc string decryption"
        cape_options = "bp0=$decode+17,action0=string:edx,count=1,typestring=Stealc Strings"
        packed = "d0c824e886f14b8c411940a07dc133012b9eed74901b156233ac4cac23378add"
    strings:
        $decode = {51 8B 15 [4] 52 8B 45 ?? 50 E8 [4] 83 C4 0C 6A 04 6A 00 8D 4D ?? 51 FF 15 [4] 83 C4 0C 8B 45 ?? 8B E5 5D C3}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule win_stealc_w0 {
   meta:
       malware = "Stealc"
       description = "Find standalone Stealc sample based on decryption routine or characteristic strings"
       source = "SEKOIA.IO"
       reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"
       classification = "TLP:CLEAR"
       hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
       author = "crep1x"
       malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealc"
       malpedia_version = "20230221"
       malpedia_license = "CC BY-NC-SA 4.0"
       malpedia_sharing = "TLP:WHITE"
       malpedia_rule_date = "20230221"
       malpedia_hash = ""
   strings:
       $dec = { 55 8b ec 8b 4d ?? 83 ec 0c 56 57 e8 ?? ?? ?? ?? 6a 03 33 d2 8b f8 59 f7 f1 8b c7 85 d2 74 04 } //deobfuscation function

       $str01 = "------" ascii
       $str02 = "Network Info:" ascii
       $str03 = "- IP: IP?" ascii
       $str04 = "- Country: ISO?" ascii
       $str05 = "- Display Resolution:" ascii
       $str06 = "User Agents:" ascii
       $str07 = "%s\\%s\\%s" ascii

   condition:
       uint16(0) == 0x5A4D and ($dec or 5 of ($str*))
}

rule malware_Stealc_str {
    meta:
        description = "Stealc infostealer"
        author = "JPCERT/CC Incident Response Group"
        hash = "c9bcdc77108fd94f32851543d38be6982f3bb611c3a1115fc90013f965ed0b66"


    strings:
        $decode_code = {
          68 D0 07 00 00
          6A 00
          8D 85 ?? ?? ?? ??
          50
          FF 15 ?? ?? ?? ??
          83 C4 0C
          C7 85 ?? ?? ?? ?? 00 00 00 00
          EB ??
          8B 8D ?? ?? ?? ??
          83 C1 01
          89 8D ?? ?? ?? ??
          81 BD ?? ?? ?? ?? 00 01 00 00
        }
        $anti_code1 = {6A 04 68 00 30 00 00 68 C0 41 C8 17 6A 00 FF 15}
        $anti_code2 = {90 8A C0 68 C0 9E E6 05 8B 45 ?? 50 E8}
        $s1 = "- IP: IP?" ascii
        $s2 = "- Country: ISO?" ascii
        $s3 = "- Display Resolution:" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       ($decode_code or all of ($anti_code*) or all of ($s*))
}

rule Windows_Trojan_Stealc_b8ab9ab5 {
    meta:
        author = "Elastic Security"
        id = "b8ab9ab5-5731-4651-b982-03ad8fe347fb"
        fingerprint = "49253b1d1e39ba25b2d3b622d00633b9629715e65e1537071b0f3b0318b7db12"
        creation_date = "2024-03-13"
        last_modified = "2024-03-21"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "0d1c07c84c54348db1637e21260dbed09bd6b7e675ef58e003d0fe8f017fd2c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_str_decrypt = { 55 8B EC 83 EC ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 83 C0 ?? 50 }
        $seq_lang_check = { 81 E9 19 04 00 00 89 4D ?? 83 7D ?? ?? 77 ?? 8B 55 ?? 0F B6 82 ?? ?? ?? ?? FF 24 85 ?? ?? ?? ?? }
        $seq_mem_check_constant = { 72 09 81 7D F8 57 04 00 00 73 08 }
        $seq_hwid_algo = { 8B 08 69 C9 0B A3 14 00 81 E9 51 75 42 69 8B 55 08 }
        $str1 = "- Country: ISO?" ascii fullword
        $str2 = "%d/%d/%d %d:%d:%d" ascii fullword
        $str3 = "%08lX%04lX%lu" ascii fullword
        $str4 = "\\Outlook\\accounts.txt" ascii fullword
        $str5 = "/c timeout /t 5 & del /f /q" ascii fullword
    condition:
        (2 of ($seq*) or 4 of ($str*))
}

rule Windows_Trojan_Stealc_a2b71dc4 {
    meta:
        author = "Elastic Security"
        id = "a2b71dc4-4041-4c1f-b546-a2b6947702d1"
        fingerprint = "9eeb13fededae39b8a531fa5d07eaf839b56a1c828ecd11322c604962e8b1aec"
        creation_date = "2024-03-13"
        last_modified = "2024-03-21"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "0d1c07c84c54348db1637e21260dbed09bd6b7e675ef58e003d0fe8f017fd2c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_1 = { 8B C6 C1 E8 02 33 C6 D1 E8 33 C6 C1 E8 02 33 C6 83 E0 01 A3 D4 35 61 00 C1 E0 0F 66 D1 E9 66 0B C8 }
        $seq_2 = { FF D3 8B 4D ?? E8 [4] 6A ?? 33 D2 5F 8B C8 F7 F7 85 D2 74 ?? }
        $seq_3 = { 33 D2 8B F8 59 F7 F1 8B C7 3B D3 76 04 2B C2 03 C1 }
        $seq_4 = { 6A 7C 58 66 89 45 FC 8D 45 F0 50 8D 45 FC 50 FF 75 08 C7 45 F8 01 }
    condition:
        2 of ($seq*)
}

rule Windows_Trojan_Stealc_5d3f297c {
    meta:
        author = "Elastic Security"
        id = "5d3f297c-b812-401a-8671-2e00369cd6f2"
        fingerprint = "ff90bfcb28bb3164fb11da5f35f289af679805f7e4047e48d97ae89e5b820dcd"
        creation_date = "2024-03-05"
        last_modified = "2024-06-13"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "885c8cd8f7ad93f0fd43ba4fb7f14d94dfdee3d223715da34a6e2fbb4d25b9f4"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 08 C7 45 F8 00 00 00 00 83 7D 08 00 74 4A 83 7D 0C 00 74 44 8B 45 0C 83 C0 01 50 6A 40 ?? ?? ?? ?? ?? ?? 89 45 F8 83 7D F8 00 74 2C C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 }
    condition:
        all of them
}


rule win_stealc_bytecodes_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Bytecodes present in Stealc decoding routine"
		sha_256 = "74ff68245745b9d4cec9ef3c539d8da15295bdc70caa6fdb0632acdd9be4130a"
		sha_256 = "9f44a4cbc30e7a05d7eb00b531a9b3a4ada5d49ecf585b48892643a189358526"

	strings:
		$s1 = {8b 4d f0 89 4d f8 8b 45 f8 c1 e0 03 33 d2 b9 06 00 00 00 f7 f1 8b e5 5d c2 04 00}

	condition:

		(all of ($s*))

}

rule Stealer_Stealc
{
	meta:
		author = "Still"
		component_name = "N/A"
		date = "2024-10-04"
		description = "attempts to match instructions/strings found in Stealc"
		malpedia_family = "win.stealc"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "2E84B07EA9D624E7D3DBE3F95C6DD8BA"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "858820c6-ce4e-41c8-9a5b-9098dd2a4746"
	strings:
		$str_1 = "-nop -c \"iex(New-Object Net.WebClient).DownloadString('" ascii
		$str_2 = "SELECT service, encrypted_token FROM token_service" ascii
		$str_3 = "browser: FileZilla\n" ascii
		$str_4 = "ChromeFuckNewCookies" ascii
		$str_5 = "/c timeout /t 10 & del /f /q \"" ascii
	/*
	0x419750 55                            push ebp
	0x419751 8BEC                          mov ebp, esp
	0x419753 51                            push ecx
	0x419754 C745FC00000000                mov dword ptr [ebp - 4], 0
	0x41975b 64A130000000                  mov eax, dword ptr fs:[30h]
	0x419761 8B400C                        mov eax, dword ptr [eax + 0ch]
	0x419764 8B400C                        mov eax, dword ptr [eax + 0ch]
	0x419767 8B00                          mov eax, dword ptr [eax]
	0x419769 8B00                          mov eax, dword ptr [eax]
	0x41976b 8B4018                        mov eax, dword ptr [eax + 18h]
	0x41976e 8945FC                        mov dword ptr [ebp - 4], eax
	0x419771 8B45FC                        mov eax, dword ptr [ebp - 4]
	0x419774 8BE5                          mov esp, ebp
	0x419776 5D                            pop ebp
	0x419777 C3                            ret
	 */
		$inst_low_match_peb = {
			55
			8B EC
			51
			C7 45 ?? 00 00 00 00
			64 A1 ?? ?? ?? ??
			8B 40 ??
			8B 40 ??
			8B 00
			8B 00
			8B 40 ??
			89 45 ??
			8B 45 ??
			8B E5
			5D
			C3
		}
	/*
	0x4046e6 034DF4                        add ecx, dword ptr [ebp - 0ch]
	0x4046e9 0FBE19                        movsx ebx, byte ptr [ecx]
	0x4046ec 8B550C                        mov edx, dword ptr [ebp + 0ch]
	0x4046ef 52                            push edx
	0x4046f0 FF15E0E04100                  call dword ptr [41e0e0h]
	0x4046f6 83C404                        add esp, 4
	0x4046f9 8BC8                          mov ecx, eax
	0x4046fb 8B45F4                        mov eax, dword ptr [ebp - 0ch]
	0x4046fe 33D2                          xor edx, edx
	 */
		$inst_low_match_str_decode = {
			03 4D ??
			0F BE 19
			8B 55 ??
			52
			FF 15 ?? ?? ?? ??
			83 C4 04
			8B C8
			8B 45 ??
			33 D2
		}
	condition:
		3 of ($str_*) or all of ($inst_low_match_*)
}

rule CT_Stealc
{
    meta:
        description = "Identifies Stealc malware"
        author = "Cipher Tech Solutions"
        hashes = "0d049f764a22e16933f8c3f1704d4e50"
        reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"
        mwcp = "osacce:Stealc"
	strings:
		// 0d049f764a22e16933f8c3f1704d4e50 @ 0x00403041
		$rc4_skipkey = {
            39 18       // cmp     [eax], ebx
            75 08       // jnz     short loc_40304D
            8b 45 fc    // mov     eax, [ebp+var_4]
            88 0c 10    // mov     [eax+edx], cl
            eb 0a       // jmp     short loc_403057
            8a 00       // mov     al, [eax]
            32 c1       // xor     al, cl
            8b 4d fc    // mov     ecx, [ebp+var_4]
            88 04 11    // mov     [ecx+edx], al
		}
        $str_ip = "\x09- IP: IP?" fullword
        $str_iso = "\x09- Country: ISO?" fullword
        $str_disp = "\x09- Display Resolution: " fullword
        $str_uas = "User Agents:" fullword
	condition:
		uint16be(0) == 0x4d5a and
        (
            $rc4_skipkey or
            all of ($str_*)
        )
}


rule MALPEDIA_Win_Stealc_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "539cf538-cfac-56e1-8a82-eaf8270c6c0b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealc"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.stealc_auto.yar#L1-L108"
		license_url = "N/A"
		logic_hash = "6bf18991e2a395daac8cbfec9f407668e110581410c7e2de7aedba9cee95d9f0"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { ff15???????? 85c0 7507 c685e0feffff43 }
		$sequence_1 = { 68???????? e8???????? e8???????? 83c474 }
		$sequence_2 = { 50 e8???????? e8???????? 83c474 }
		$sequence_3 = { e8???????? e8???????? 81c480000000 e9???????? }
		$sequence_4 = { 50 e8???????? e8???????? 81c484000000 }
		$sequence_5 = { e8???????? 83c460 e8???????? 83c40c }
		$sequence_6 = { e8???????? e8???????? 83c418 6a3c }
		$sequence_7 = { ff15???????? 50 ff15???????? 8b5508 8902 }
		$sequence_8 = { 50 ff15???????? 8b5508 8902 }
		$sequence_9 = { 7405 394104 7d07 8b4908 3bca 75f0 8bf9 }

	condition:
		7 of them and filesize <4891648
}


rule fsstealc {
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "stealc"
	condition:
        Stealc or StealcAnti or StealcStrings or win_stealc_w0 or malware_Stealc_str or Windows_Trojan_Stealc_b8ab9ab5 or Windows_Trojan_Stealc_a2b71dc4 or Windows_Trojan_Stealc_5d3f297c or win_stealc_bytecodes_oct_2023 or Stealer_Stealc or CT_Stealc or MALPEDIA_Win_Stealc_Auto
}