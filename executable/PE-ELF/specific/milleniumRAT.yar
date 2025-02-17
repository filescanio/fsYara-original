rule justXworm {
    meta:
        author = "RussianPanda"
        description = "Detects XWorm RAT"
        vetted_family = "xworm"
        score = 75
        date = "3/11/2024"
        hash = "fc422800144383ef6e2e0eee37e7d6ba"
    strings:
        $s1 = "xworm" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule xworm : refined {
    meta:
        author = "jeFF0Falltrades"
        vetted_family = "xworm"
        score = 75
    strings:
        $str_xworm = "xworm" wide ascii nocase
        $str_xwormmm = "Xwormmm" wide ascii
        $str_xclient = "XClient" wide ascii
        $str_xlogger = "XLogger" wide ascii
        $str_xchat = "Xchat" wide ascii
        $str_default_log = "\\Log.tmp" wide ascii
        $str_create_proc = "/create /f /RL HIGHEST /sc minute /mo 1 /t" wide ascii
        $str_ddos_start = "StartDDos" wide ascii
        $str_ddos_stop = "StopDDos" wide ascii
        $str_timeout = "timeout 3 > NUL" wide ascii
        $byte_md5_hash = { 7e [3] 04 28 [3] 06 6f }
        $patt_config = { 72 [3] 70 80 [3] 04 }
        $load_config = { 7e [3] 04 28 [4] 28 [4] 80 [3] 04 }
        $xworm_version = /XWorm V[1-9]{1,2}\.[1-9]{1,3}/ wide


        $conf_load_decrypt = {
            7E ?? ?? ?? 04   // IL_0010: ldsfld //
            28 ?? ?? ?? ??   // IL_0015: call
            28 ?? ?? ?? ??   // IL_001A: call
            80 ?? ?? ?? 04   // IL_001F: stsfld
            7E ?? ?? ?? 04   // IL_0010: ldsfld //
            28 ?? ?? ?? ??   // IL_0015: call
            28 ?? ?? ?? ??   // IL_001A: call
            80 ?? ?? ?? 04   // IL_001F: stsfld
            7E ?? ?? ?? 04   // IL_0010: ldsfld //
            28 ?? ?? ?? ??   // IL_0015: call
            28 ?? ?? ?? ??   // IL_001A: call
            80 ?? ?? ?? 04   // IL_001F: stsfld
            7E ?? ?? ?? 04   // IL_0010: ldsfld //
            28 ?? ?? ?? ??   // IL_0015: call
            28 ?? ?? ?? ??   // IL_001A: call
            80 ?? ?? ?? 04   // IL_001F: stsfld
        }

        $conf_values_9val = { // 571344039641eef1e0d6ef50a563763f2e84ae8e444eb0918c1f15d2af60ab21
            72 ?? ?? ?? 70      // IL_0000: ldstr       "hosts"
            80 ?? ?? ?? 04      // IL_0005: stsfld
            72 ?? ?? ?? 70      // IL_000A: ldstr       "port"
            80 ?? ?? ?? 04      // IL_000F: stsfld
            72 ?? ?? ?? 70      // IL_0014: ldstr       "AESkey"
            80 ?? ?? ?? 04      // IL_0019: stsfld
            72 ?? ?? ?? 70      // IL_001E: ldstr       "delimiter"
            80 ?? ?? ?? 04      // IL_0023: stsfld
            72 ?? ?? ?? 70      // IL_0: ldstr       "groubVersion"
            80 ?? ?? ?? 04      // IL_0: stsfld
            [1-10]              // IL_0028L: dc.i4.X or dc.i4.s <X>      "sleep time"
            80 ?? ?? ?? 04      // IL_0029: stsfld
            72 ?? ?? ?? 70      // IL_0: ldstr       "fname"
            80 ?? ?? ?? 04      // IL_0: stsfld
            72 ?? ?? ?? 70      // IL_0: ldstr       "mutex-configKey"
            80 ?? ?? ?? 04      // IL_0: stsfld
            72 ?? ?? ?? 70      // IL_0: ldstr       "telegramBotID"
            80 ?? ?? ?? 04      // IL_0: stsfld
            2a                  // ret
        }




    condition:
        uint16(0) == 0x5A4D and 4 of them and #patt_config >= 5 and #load_config >= 4
 }
