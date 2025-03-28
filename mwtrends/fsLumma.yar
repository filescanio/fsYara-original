rule Lumma
{
	meta:
		author = "kevoreilly"
		description = "Lumma Payload"
		cape_type = "Lumma Payload"
		packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
		ruleset = "Lumma.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/3c6d7d4f232e43db68ca2dd711f5e9d8e9e033cb/data/yara/CAPE/Lumma.yar"
		license = "Other"
		score = 75

	strings:
		$c2 = {8D 44 24 ?? 50 89 4C 24 ?? FF 31 E8 [4] 83 C4 08 B8 FF FF FF FF}
		$peb = {8B 44 24 04 85 C0 74 13 64 8B 0D 30 00 00 00 50 6A 00 FF 71 18 FF 15}
		$remap = {C6 44 24 20 00 C7 44 24 1C C2 00 00 90 C7 44 24 18 00 00 FF D2 C7 44 24 14 00 BA 00 00 C7 44 24 10 B8 00 00 00 8B ?? 89 44 24 11}

	condition:
		uint16(0)==0x5a4d and 
		any of them
}

rule win_lumma_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.lumma."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		ruleset = "win.lumma_auto.yar"
		repository = "malpedia/signator-rules"
		source_url = "https://github.com/malpedia/signator-rules/blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.lumma_auto.yar"
		score = 75

	strings:
		$sequence_0 = { 57 53 ff767c ff7678 }
		$sequence_1 = { ffd0 83c40c 894648 85c0 }
		$sequence_2 = { ff5130 83c410 85c0 7407 }
		$sequence_3 = { ff7678 ff7644 ff563c 83c414 }
		$sequence_4 = { ff770c ff37 ff7134 ff5130 }
		$sequence_5 = { ff7608 ff7044 ff503c 83c414 }
		$sequence_6 = { 894610 8b461c c1e002 50 }
		$sequence_7 = { 833800 740a e8???????? 833822 }
		$sequence_8 = { 83c40c 6a02 6804010000 e8???????? }
		$sequence_9 = { 017e78 83567c00 017e68 83566c00 }
		$sequence_10 = { 89e5 8b550c 6bd204 89d1 }
		$sequence_11 = { 41 5d 41 5b 41 5c }
		$sequence_12 = { 48 83ec28 0f05 48 83c428 49 }

	condition:
		7 of them and 
		filesize <1115136
}

rule Detect_lumma_stealer : lumma
{
	meta:
		description = "Detect_lumma_stealer"
		author = "@malgamy12"
		date = "2023/1/7"
		license = "DRL 1.1"
		hash = "61b9701ec94779c40f9b6d54faf9683456d02e0ee921adbb698bf1fee8b11ce8"
		hash = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"
		hash = "9b742a890aff9c7a2b54b620fe5e1fcfa553648695d79c892564de09b850c92b"
		hash = "60247d4ddd08204818b60ade4bfc32d6c31756c574a5fe2cd521381385a0f868"
		ruleset = "lumma.yara"
		repository = "MalGamy/YARA_Rules"
		source_url = "https://github.com/MalGamy/YARA_Rules/blob/1f538fcd5fe6d8aeec6c8a8394a785b69872b7a7/lumma.yara"
		score = 75

	strings:
		$s1 = "- PC:" ascii
		$s2 = "- User:" ascii
		$s3 = "- Screen Resoluton:" ascii
		$s4 = "- Language:" ascii
		$op = {0B C8 69 F6 [4] 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 07 C1 E1 ?? 83 C7 ?? 0B C8 69 C9 [4] 8B C1 C1 E8 ?? 33 C1 69 C8 [4] 33 F1}

	condition:
		uint16(0)==0x5A4D and 
		$op and 
		all of ($s*)
}

rule win_lumma_simple_strings
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/09/13"
		description = ""
		sha_256 = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"
		ruleset = "win_lumma _simple_sep_2023.yar"
		repository = "embee-research/Yara-detection-rules"
		source_url = "https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_lumma%20_simple_sep_2023.yar"
		score = 75

	strings:
		$s1 = "Binedx765ance Chaedx765in Waledx765let" wide
		$s2 = "%appdaedx765ta%\\Moedx765zilla\\Firedx765efox\\Profedx765iles"
		$s3 = "\\Locedx765al Extensedx765ion Settinedx765gs\\"
		$s4 = "%appdedx765ata%\\Opedx765era Softwedx765are\\Opedx765era GX Staedx765ble"
		$o1 = {57 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 62 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}
		$o2 = {4f 00 70 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 72 00 61 00 20 00 4e 00 65 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 6e 00}
		$o3 = {4c 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 67 00 69 00 6e 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}

	condition:
		uint16(0)==0x5a4d and 
		filesize <5000KB and 
		(( all of ($s*)) or 
			( all of ($o*)))
}

rule LummaStealer
{
	meta:
		author = "ditekSHen"
		description = "Detects Lumma Stealer"
		cape_type = "LummaStealer Payload"
		ruleset = "LummaStealer.yar"
		repository = "CAPESandbox/community"
		source_url = "https://github.com/CAPESandbox/community/blob/ed71b5eb9179e25174c1a2d0fe451e25cbf97dd1/data/yara/CAPE/deprecated/LummaStealer.yar"
		score = 75

	strings:
		$x1 = /Lum[0-9]{3}xedmaC2,\sBuild/ ascii
		$x2 = /LID\(Lu[0-9]{3}xedmma\sID\):/ ascii
		$s1 = /os_c[0-9]{3}xedrypt\.encry[0-9]{3}xedpted_key/ fullword ascii
		$s2 = "c2sock" wide
		$s3 = "c2conf" wide
		$s4 = "TeslaBrowser/" wide
		$s5 = "Software.txt" fullword wide
		$s6 = "SysmonDrv" fullword
		$s7 = "*.eml" fullword wide nocase
		$s8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
		$s9 = "- Screen Resoluton:" ascii
		$s10 = "lid=%s" ascii
		$s11 = "&ver=" ascii
		$s12 = "769cb9aa22f4ccc412f9cbc81feedd" fullword wide
		$s13 = "gapi-node.io" fullword ascii

	condition:
		uint16(0)==0x5a4d and 
		( all of ($x*) or 
			(1 of ($x*) and 
				2 of ($s*)) or 
			5 of ($s*) or 
			7 of them )
}

rule CAPE_Lumma : FILE
{
	meta:
		description = "Lumma config extraction"
		author = "kevoreilly"
		id = "846ddd61-897d-5990-a480-6af3f69d4eff"
		date = "2024-01-05"
		modified = "2024-01-05"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/Lumma.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "1ac96e29150f24c098a6ac1e97fab71812976ddb748368cbdea7055a93a38a38"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Lumma Payload"
		packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
		ruleset = "CAPE_Lumma.yar"
		repository = "she11der/YARA"

	strings:
		$c2 = {B8 FF FF FF FF 0F 1F 84 00 00 00 00 00 80 7C [2] 00 8D 40 01 75 F6 C7 44 [2] 00 00 00 00 8D}
		$peb = {8B 44 24 04 85 C0 74 13 64 8B 0D 30 00 00 00 50 6A 00 FF 71 18 FF 15}
		$decode = {88 1F 47 0F B6 19 41 84 DB 75 F5 C6 07 00 0F B6 1E 84 DB 74 16 46 66 2E 0F 1F 84 00 00 00 00 00}

	condition:
		uint16(0)==0x5a4d and 
		any of them
}

rule detect_Lumma_stealer : Lumma
{
	meta:
		description = "detect_Lumma_stealer"
		author = "@malgamy12"
		date = "2022-11-3"
		license = "DRL 1.1"
		hunting = "https://www.hybrid-analysis.com/sample/f18d0cd673fd0bd3b071987b53b5f97391a56f6e4f0c309a6c1cee6160f671c0"
		hash1 = "19b937654065f5ee8baee95026f6ea7466ee2322"
		hash2 = "987f93e6fa93c0daa0ef2cf4a781ca53a02b65fe"
		hash3 = "70517a53551269d68b969a9328842cea2e1f975c"
		hash4 = "9b7b72c653d07a611ce49457c73ee56ed4c4756e"
		hash5 = "4992ebda2b069281c924288122f76556ceb5ae02"
		hash6 = "5c67078819246f45ff37d6db81328be12f8fc192"
		hash7 = "87fe98a00e1c3ed433e7ba6a6eedee49eb7a9cf9"
		ruleset = "lumma_stealer.yara"
		repository = "MalGamy/YARA_Rules"
		source_url = "https://github.com/MalGamy/YARA_Rules/blob/1f538fcd5fe6d8aeec6c8a8394a785b69872b7a7/lumma_stealer.yara"
		score = 75

	strings:
		$m1 = "LummaC\\Release\\LummaC.pdb" ascii fullword
		$s1 = "Cookies.txt" ascii
		$s2 = "Autofills.txt" ascii
		$s3 = "ProgramData\\config.txt" ascii
		$s4 = "ProgramData\\softokn3.dll" ascii
		$s5 = "ProgramData\\winrarupd.zip" ascii
		$chunk_1 = {C1 E8 ?? 33 C6 69 C8 ?? ?? ?? ?? 5F 5E 8B C1 C1 E8 ??}

	condition:
		$m1 or 
		(4 of ($s*) and 
			$chunk_1)
}

rule win_lumma_update_simple_strings_sep_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/09/13"
		description = ""
		sha_256 = "898a2bdbbb33ccd63b038c67d217554a668a52e9642874bd0f57e08153e6e5be"
		ruleset = "win_lumma_updated_sep_2023.yar"
		repository = "embee-research/Yara-detection-rules"
		source_url = "https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_lumma_updated_sep_2023.yar"
		score = 75

	strings:
		$s1 = "Do you want to run a malware ?" wide
		$s2 = "c2sock" wide
		$s3 = "TeslaBrowser/5" wide
		$s4 = "Crypt build to disable this message" wide

	condition:
		uint16(0)==0x5a4d and 
		filesize <5000KB and 
		( all of ($s*))
}

rule win_lumma_auto_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-03-28"
		version = "1"
		description = "Detects win.lumma."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
		malpedia_rule_date = "20230328"
		malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
		malpedia_version = "20230407"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		original_yara_name = "win_lumma_auto"
		ruleset = "win.lumma_auto.yar"
		repository = "linuxwellness/secure_linux"
		source_url = "https://github.com/linuxwellness/secure_linux/blob/5dc90d8ad2493a08aebf2441c8b8ae8ae49a22e8/yara_rules/win.lumma_auto.yar"
		score = 75

	strings:
		$sequence_0 = { 57 8bfe c1ef02 0fb602 83ee04 }
		$sequence_1 = { e8???????? 89460c 8b461c c1e002 }
		$sequence_2 = { 57 8bfe c1ef02 0fb602 }
		$sequence_3 = { 89460c 8b461c c1e002 50 e8???????? 894610 }
		$sequence_4 = { 50 e8???????? 894604 8b461c c1e002 }
		$sequence_5 = { 83fe04 725d 57 8bfe }
		$sequence_6 = { 50 e8???????? 894614 8b461c c1e002 50 }
		$sequence_7 = { 56 57 8bf2 8bd9 6a2e 56 }
		$sequence_8 = { 8bfe c1ef02 0fb602 83ee04 33c1 c1e908 0fb6c0 }
		$sequence_9 = { e8???????? 894610 8b461c c1e002 50 e8???????? 894614 }

	condition:
		7 of them and 
		filesize <413552
}

rule LummaC2
{
	meta:
		author = "RussianPanda"
		description = "LummaC2 Detection"
		ruleset = "e0f84a65a11819e1c5b5fcacc9cffc11adbefa91.yar"
		repository = "LeakIX/yara-repo-otx"
		source_url = "https://github.com/LeakIX/yara-repo-otx/blob/211ad0b9355b0b1aafc850494449a2603f012a07/e0f84a65a11819e1c5b5fcacc9cffc11adbefa91.yar"
		score = 75

	strings:
		$p1 = "lid=%s&j=%s&ver"
		$p2 = {89 ca 83 e2 03 8a 54 14 08 32 54 0d 04}

	condition:
		all of them and 
		filesize <=500KB
}

rule Lumma_1
{
	meta:
		author = "kevoreilly"
		description = "Lumma config extraction"
		cape_options = "bp0=$decode+5,action0=string:ebp,count=0,bp1=$patch+8,action1=skip,typestring=Lumma Config"
		packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
		original_yara_name = "Lumma"
		ruleset = "Lumma.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/3c6d7d4f232e43db68ca2dd711f5e9d8e9e033cb/analyzer/windows/data/yara/Lumma.yar"
		license = "Other"
		score = 75

	strings:
		$c2 = {8D 44 24 ?? 50 89 4C 24 ?? FF 31 E8 [4] 83 C4 08 B8 FF FF FF FF}
		$decode = {C6 44 05 00 00 83 C4 2C 5E 5F 5B 5D C3}
		$patch = {66 C7 0? 00 00 8B 46 1? C6 00 01 8B}

	condition:
		uint16(0)==0x5a4d and 
		2 of them
}

rule LummaRemap
{
	meta:
		author = "kevoreilly"
		description = "Lumma ntdll-remap bypass"
		cape_options = "ntdll-remap=0"
		packed = "7972cbf2c143cea3f90f4d8a9ed3d39ac13980adfdcf8ff766b574e2bbcef1b4"
		ruleset = "Lumma.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/3c6d7d4f232e43db68ca2dd711f5e9d8e9e033cb/analyzer/windows/data/yara/Lumma.yar"
		license = "Other"
		score = 75

	strings:
		$remap = {C6 44 24 20 00 C7 44 24 1C C2 00 00 90 C7 44 24 18 00 00 FF D2 C7 44 24 14 00 BA 00 00 C7 44 24 10 B8 00 00 00 8B ?? 89 44 24 11}

	condition:
		uint16(0)==0x5a4d and 
		any of them
}

rule win_lumma_auto_2
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.lumma."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"
		original_yara_name = "win_lumma_auto"
		ruleset = "b7e8d596b5952fbf9c7d3a9f312c9de92a3a9481.yar"
		repository = "kid0604/yara-rules"
		source_url = "https://github.com/kid0604/yara-rules/blob/c081883d8387ba2a898b84bdbefd40fa910a2b31/executable_windows/b7e8d596b5952fbf9c7d3a9f312c9de92a3a9481.yar"
		score = 75

	strings:
		$sequence_0 = { 57 53 ff767c ff7678 }
		$sequence_1 = { 53 49 83fc00 75e8 8b4508 49 89ca }
		$sequence_2 = { e8???????? ff7614 e8???????? ff7608 e8???????? 83c414 83c8ff }
		$sequence_3 = { 4d 6be404 49 83ec04 }
		$sequence_4 = { 41 5b 41 5c }
		$sequence_5 = { c1e002 50 e8???????? 894614 8b461c c1e002 }
		$sequence_6 = { 0fb64203 83c204 33c1 c1e908 }
		$sequence_7 = { 41 5a cb 55 89e5 8b550c }
		$sequence_8 = { 4d 6bdb08 4c 01dc }
		$sequence_9 = { 50 e8???????? 894604 8b461c }
		$sequence_10 = { 41 8b0a 41 8b5204 }
		$sequence_11 = { 4d 89f3 49 83eb04 }
		$sequence_12 = { 57 8bf2 8bd9 6a2e 56 }
		$sequence_13 = { 03c0 3bc2 0f47d0 e8???????? 85c0 }
		$sequence_14 = { c1e002 50 e8???????? 89460c 8b461c c1e002 }

	condition:
		7 of them and 
		filesize <838656
}

rule Lumma_alt_2
{
	meta:
		author = "kevoreilly"
		description = "Lumma Payload"
		cape_type = "Lumma Payload"
		packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
		os = "windows"
		filetype = "executable"
		ruleset = "604563f06960b6a0512348c9475401b1abdb2c70.yar"
		repository = "kid0604/yara-rules"
		source_url = "https://github.com/kid0604/yara-rules/blob/c081883d8387ba2a898b84bdbefd40fa910a2b31/executable_windows/604563f06960b6a0512348c9475401b1abdb2c70.yar"
		score = 75

	strings:
		$c2 = {B8 FF FF FF FF 0F 1F 84 00 00 00 00 00 80 7C [2] 00 8D 40 01 75 F6 C7 44 [2] 00 00 00 00 8D}
		$peb = {8B 44 24 04 85 C0 74 13 64 8B 0D 30 00 00 00 50 6A 00 FF 71 18 FF 15}
		$decode = {88 1F 47 0F B6 19 41 84 DB 75 F5 C6 07 00 0F B6 1E 84 DB 74 16 46 66 2E 0F 1F 84 00 00 00 00 00}
		$remap = {C6 44 24 20 00 C7 44 24 1C C2 00 00 90 C7 44 24 18 00 00 FF D2 C7 44 24 14 00 BA 00 00 C7 44 24 10 B8 00 00 00 8B ?? 89 44 24 11}

	condition:
		uint16(0)==0x5a4d and 
		any of them
}

rule fsLumma
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "lumma"
		score = 75

	condition:
		Lumma or 
		win_lumma_auto or 
		Detect_lumma_stealer or 
		win_lumma_simple_strings or 
		LummaStealer or 
		CAPE_Lumma or 
		detect_Lumma_stealer or 
		win_lumma_update_simple_strings_sep_2023 or 
		win_lumma_auto_1 or 
		LummaC2 or 
		Lumma_1 or 
		LummaRemap or 
		win_lumma_auto_2 or 
		Lumma_alt_2
}

