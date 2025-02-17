import "pe"

rule milleniumRAT : refined {
    meta:
        author = "OPSWAT"
        description = "Detects Millenium RAT"
        date = "17-02-2025"
        vetted_family = "MilleniumRAT"
        score = 75
    strings:
        $st_eof = "[EOF]" wide
        $st_av = "Installed antivirus" wide
        $st_tg = "Telegram data" wide
        $st_buildmsg = "Started a build with a blocked private key!" wide
        $checklink_github = "raw.githubusercontent.com" wide
        $checklink_pasteCom = "pastebin.com" wide
        $checklink_pasteOrg = "pastebin.org" wide
        $netw_proc0 = "processhacker" wide
        $netw_proc1 = "netstat" wide
        $netw_proc2 = "netmon" wide
        $netw_proc3 = "tcpview" wide
        $netw_proc4 = "wireshark" wide
        $netw_proc5 = "filemon" wide
        
        $enc_ftype0 = ".lnk" wide
        $enc_ftype1 = ".png" wide
        $enc_ftype2 = ".jpg" wide
        $enc_ftype3 = ".bmp" wide
        $enc_ftype4 = ".txt" wide
        $enc_ftype5 = ".doc" wide
        $enc_ftype6 = ".txt" wide
        $enc_ftype7 = ".docx" wide
        $enc_ftype8 = ".xls" wide
        $enc_ftype9 = ".xlsx" wide
        $enc_ftype10 = ".doc" wide
        $enc_ftype11 = ".ppt" wide
        $enc_ftype12 = ".pptx" wide
        $enc_ftype13 = ".csv" wide
        $enc_ftype14 = ".sql" wide
        $enc_ftype15 = ".php" wide
        $enc_ftype16 = ".ppt" wide
        $enc_ftype17 = ".html" wide
        $enc_ftype18 = ".xml" wide
        $enc_ftype19 = ".jar" wide
        $enc_ftype21 = ".py" wide

        $grab_ftype0 = ".pdf" wide
        $grab_ftype1 = ".rdp" wide
        $grab_ftype2 = ".txt" wide
        $grab_ftype3 = ".rtf" wide
        $grab_ftype4 = ".doc" wide
        $grab_ftype5 = ".docx" wide
        $grab_ftype6 = ".xls" wide
        $grab_ftype7 = ".xlsx" wide
        $grab_ftype8 = ".odt" wide
        $grab_ftype9 = ".sql" wide
        $grab_ftype10 = ".php" wide
        $grab_ftype11 = ".py" wide
        $grab_ftype12 = "html" wide
        $grab_ftype13 = ".xml" wide
        $grab_ftype14 = ".json" wide
        $grab_ftype15 = ".csv" wide
	
        $config_load  = {
            (06 | 07 | 08 | 09 | 11 ??)     // IL: ldloc.2
            [1-2]                           // IL: ldc.i4.X or ldc.i4.s 
            9A                              // IL: ldelem.ref
            6F ?? ?? ?? 0A                  // IL: callvirt  instance string [mscorlib]System.Object::ToString()
            28 ?? ?? ?? 06                  // IL: call      string TelegramRAT.Program::Rot13(string)
            80 ?? ?? ?? 04                  // IL: stsfld    string TelegramRAT.config::___
        }
	

    condition:
        uint16(0) == 0x5A4D and
	   pe.imports("mscoree.dll") and // dotnet PE
	   3 of ($st*) and
       1 of ($checklink*) and
       4 of ($netw*) and
       15 of ($enc*) and
       10 of ($grab*) and
       #config_load >= 8
       //#patt_config >= 5 and #load_config >= 4
 }
