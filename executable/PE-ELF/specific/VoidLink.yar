rule voidlink_implant : malware {
    meta:
        name        = "voidlink_implant"
        category    = "persistence"
        description = "Detects strings which are a part of the VoidLink implant."
        author      = "SquiblydooBlog"
        created     = "2026-01-16"
        reliability = 50
        tlp         = "TLP:CLEAR"
		reference   = "https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/"
        sample1     = "15cb93d38b0a4bd931434a501d8308739326ce482da5158eb657b0af0fa7ba49"      
        sample2     = "05eac3663d47a29da0d32f67e10d161f831138e10958dcd88b9dc97038948f69"
        sample3     = "28c4a4df27f7ce8ced69476cc7923cf56625928a7b4530bc7b484eec67fe3943"
        sample4     = "4c4201cc1278da615bacf48deef461bf26c343f8cbb2d8596788b41829a39f3f"
        sample5     = "6850788b9c76042e0e29a318f65fceb574083ed3ec39a34bc64a1292f4586b41"
        sample6     = "6dcfe9f66d3aef1efd7007c588a59f69e5cd61b7a8eca1fb89a84b8ccef13a2b"
        score       = 80

    strings:
        $credential_theft_1 = "total_harvests\""
		$credential_theft_2 = ".git-credentials"
		$credential_theft_3 = "\"ssh_config_found"

		$debugging_1 = "failed to kill process" fullword ascii
		$debugging_2 = "ProcessAlreadyExec" fullword ascii
		$debugging_3 = "Failed to connect to C2" fullword ascii
		$debugging_4 = "error: [ChainExecutor] Failed to spawn shell: error: [ChainExecutor] Failed to wait for shell: " fullword ascii

		$stealth_1 = "stealth_manager" fullword ascii
		$stealth_2 = "stealth features failed" fullword ascii
		$stealth_3 = "Stealth activation failed" fullword ascii

    condition:
        uint16(0) == 0x457f and filesize < 6000KB and all of ($credential_theft*) and 3 of ($debugging*) and 1 of ($stealth*)
}




import "elf"

rule Actor_APT_CN_Multiple_MAL_LNX_ELF_InitialStages_VoidLink_ELFProperties_Jan26
{
    meta:
        rule_id = "353d6da4-4e96-4f1a-9280-db6b8b3753ca"
        date = "20-01-2026"
        author = "Rustynoob619"
        description = "Detects stages 1 and 2 which drop VoidLink Linux Backdoor used by Chinese Nexus Threat Actors based on TELFHash"
        source = "https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/"
        filehash = "13025f83ee515b299632d267f94b37c71115b22447a0425ac7baed4bf60b95cd"
        score = 75

    condition:
        uint32be(0) == 0x7f454c46
        and (elf.telfhash() == "t12db0120802d820326b9094d00e5e2e0d315501c58b0d2d0850844300514cf18251e03c" 
        or elf.telfhash() == "t150b0120c730203b5d781d07b078413062ca014810616d4c842414304199832cb30c1b3")
        and filesize < 250KB

}




rule Actor_APT_CN_Multiple_MAL_LNX_ELF_Backdoor_VoidLink_Strings_Jan26
{
    meta:
        rule_id = "1904ff5d-edb2-4116-a2c4-51957b89d517"
        date = "19-01-2026"
        author = "Rustynoob619"
        description = "Detects VoidLink Linux Backdoor used by Chinese Nexus Threat Actors based on strings"
        source = "https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/"
        filehash = "05eac3663d47a29da0d32f67e10d161f831138e10958dcd88b9dc97038948f69"
        score = 80

    strings:

        $unq = {4167656e742049443a2020204332205461726765743a203a} //Agent ID: C2 Target: :

        $hrtbt1 = "heartbeat_mode" ascii
        $hrtbt2 = "total_heartbeats" ascii
        $hrtbt3 = "heartbeat_jitter" ascii
        $hrtbt4 = "/api/v2/heartbeat" ascii fullword

        $beacon1 = "beacon_random_delay" ascii fullword
        $beacon2 = "beacon_net_accept" ascii fullword
        $beacon3 = "beacon_send_result" ascii fullword
        $beacon4 = "beacon_net_connect" ascii fullword
        $beacon5 = "beacon_sleep_ms" ascii fullword
        $beacon6 = "beacon_net_listen" ascii fullword
        $beacon7 = "beacon_geteuid" ascii fullword
        $beacon8 = "beacon_get_task_id" ascii fullword
        $beacon9 = "beacon_stealth_exec" ascii fullword
        $beacon10 = "beacon_base64_encode" ascii fullword

    condition:
        uint32be(0) == 0x7f454c46
        and (
            $unq or 
            (
                2 of ($hrtbt*)
                and 3 of ($beacon*)
            )
        )
        and filesize < 6MB

}