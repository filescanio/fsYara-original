rule win_gcleaner_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.gcleaner."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gcleaner"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		ruleset = "win.gcleaner_auto.yar"
		repository = "malpedia/signator-rules"
		source_url = "https://github.com/malpedia/signator-rules/blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.gcleaner_auto.yar"
		score = 75

	strings:
		$sequence_0 = { 8d8d70feffff 8d45b0 0f4345b0 51 50 }
		$sequence_1 = { 8bd0 c645fc04 8d4dd8 e8???????? 83c410 }
		$sequence_2 = { 660fd64010 8345e418 eb10 8d4dc8 }
		$sequence_3 = { 660fd64610 c742e000000000 c742e40f000000 c642d000 8b42e8 894618 }
		$sequence_4 = { e8???????? 8d8d60ffffff e8???????? 6a00 6a00 }
		$sequence_5 = { c642d000 8b42e8 894618 8d42ec 83c61c 3bc7 }
		$sequence_6 = { eb10 8d4dc8 51 50 }
		$sequence_7 = { 7438 8035????????2e 8035????????2e 8035????????2e 8035????????2e 8035????????2e 8035????????2e }
		$sequence_8 = { 52 51 e8???????? 83c408 85ff 0f8807010000 }
		$sequence_9 = { c645fc02 83fa10 722c 8b4dc8 42 8bc1 }

	condition:
		7 of them and 
		filesize <540672
}

rule win_gcleaner
{
	meta:
		author = "Johannes Bader @viql"
		date = "2022-05-29"
		version = "v1.0"
		description = "detects GCleaner"
		tlp = "TLP:WHITE"
		malpedia_family = "win.gcleaner"
		hash1_md5 = "8151e61aec021fa04bce8a30ea052e9d"
		hash1_sha1 = "4b972d2e74a286e9663d25913610b409e713befd"
		hash1_sha256 = "868fceaa4c01c2e2ceee3a27ac24ec9c16c55401a7e5a7ca05f14463f88c180f"
		hash2_md5 = "7526665a9d5d3d4b0cfffb2192c0c2b3"
		hash2_sha1 = "13bf754b44526a7a8b5b96cec0e482312c14838c"
		hash2_sha256 = "bb5cd698b03b3a47a2e55a6be3d62f3ee7c55630eb831b787e458f96aefe631b"
		hash3_md5 = "a39e68ae37310b79c72025c6dfba0a2a"
		hash3_sha1 = "ae007e61c16514a182d21ee4e802b7fcb07f3871"
		hash3_sha256 = "c5395d24c0a1302d23f95c1f95de0f662dc457ef785138b0e58b0324965c8a84"
		ruleset = "gcleaner.yar"
		repository = "conexioninversa/WOPR"
		source_url = "https://github.com/conexioninversa/WOPR/blob/65ab547df2afe8b013933bf9fa30fc3880827987/yara/gcleaner.yar"
		score = 75

	strings:
		$accept = "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1"
		$accept_lang = "Accept-Language: ru-RU,ru;q=0.9,en;q=0.8"
		$accept_charset = "Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1"
		$accept_encoding = "Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0"
		$unkown = "<unknown>"
		$cmd1 = "\" & exit"
		$cmd2 = "\" /f & erase "
		$cmd3 = "/c taskkill /im \""
		$anti1 = " Far "
		$anti2 = "roxifier"
		$anti3 = "HTTP Analyzer"
		$anti4 = "Wireshark"
		$anti5 = "NetworkMiner"
		$mix1 = "mixshop"
		$mix2 = "mixtwo"
		$mix3 = "mixnull"
		$mix4 = "mixazed"

	condition:
		uint16(0)==0x5A4D and 
		15 of them
}

rule win_gcleaner_auto_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-03-28"
		version = "1"
		description = "Detects win.gcleaner."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gcleaner"
		malpedia_rule_date = "20230328"
		malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
		malpedia_version = "20230407"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		original_yara_name = "win_gcleaner_auto"
		ruleset = "win.gcleaner_auto.yar"
		repository = "linuxwellness/secure_linux"
		source_url = "https://github.com/linuxwellness/secure_linux/blob/5dc90d8ad2493a08aebf2441c8b8ae8ae49a22e8/yara_rules/win.gcleaner_auto.yar"
		score = 75

	strings:
		$sequence_0 = { c645c800 0f1100 f30f7e45d8 660fd64010 8345e418 eb10 8d4dc8 }
		$sequence_1 = { 6a2f 53 e8???????? 8bf8 83c40c }
		$sequence_2 = { 660fd64010 8345e418 eb10 8d4dc8 }
		$sequence_3 = { 6a2f 53 e8???????? 8bf8 83c40c 85ff }
		$sequence_4 = { 50 8d859cfeffff 50 e8???????? c645fc03 8b45e4 }
		$sequence_5 = { 6810040000 89b5f4feffff ff15???????? 8bf8 85ff 741c 6804010000 }
		$sequence_6 = { c645fc02 8b55c4 8bc2 8b4dc0 }
		$sequence_7 = { 6a00 6810040000 ff15???????? 8bf0 85f6 7434 8d85f4feffff }
		$sequence_8 = { 66898500ffffff 8d8502ffffff 6a00 50 660fd685f8feffff }
		$sequence_9 = { f30f7e45d8 660fd64010 8345e418 eb10 8d4dc8 51 }

	condition:
		7 of them and 
		filesize <540672
}

rule win_gcleaner_auto_2
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.gcleaner."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gcleaner"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"
		original_yara_name = "win_gcleaner_auto"
		ruleset = "a8d4b7ab284b5bff7a29395a1e40b384f560eb8e.yar"
		repository = "kid0604/yara-rules"
		source_url = "https://github.com/kid0604/yara-rules/blob/c081883d8387ba2a898b84bdbefd40fa910a2b31/executable_windows/a8d4b7ab284b5bff7a29395a1e40b384f560eb8e.yar"
		score = 75

	strings:
		$sequence_0 = { 50 6a04 8d85f0feffff 50 56 ff15???????? 85c0 }
		$sequence_1 = { c742e000000000 c742e40f000000 c642d000 8b42e8 894618 8d42ec }
		$sequence_2 = { 83c404 a0???????? 84c0 743f }
		$sequence_3 = { 8d8d78ffffff e8???????? 8d8d60ffffff e8???????? 6a00 6a00 8d4dd8 }
		$sequence_4 = { e8???????? 57 8bd0 c645fc03 8d4dc0 e8???????? }
		$sequence_5 = { 50 660fd685f8feffff e8???????? 83c40c 56 }
		$sequence_6 = { 6800004080 6a00 6a00 6a00 51 }
		$sequence_7 = { 6810040000 89b5f4feffff ff15???????? 8bf8 85ff 741c 6804010000 }
		$sequence_8 = { 7419 6804010000 8d85f8feffff 50 ffb5f0feffff }
		$sequence_9 = { 8d4dc8 837ddc10 8b75c8 8b55d8 0f43ce 50 51 }

	condition:
		7 of them and 
		filesize <540672
}

rule fsGCleaner
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "gcleaner"
		score = 75

	condition:
		win_gcleaner_auto or 
		win_gcleaner or 
		win_gcleaner_auto_1 or 
		win_gcleaner_auto_2
}

