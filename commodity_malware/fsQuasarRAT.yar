rule QuasarRAT
{
    meta:
        description = "QuasarRAT super rule synthesized from public YARA rules"
        author = "yara-osint"
        date = "2026-06-22"
        vetted_family = "quasar"
        sources = "airbnb/binaryalert, CAPESandbox/community, jeFF0Falltrades/YARA-Signatures, rapid7/Rapid7-Labs, Nextron/FloRoth, TrojanDB"
        hash = "3a1d3648c53763cc3f8496f30fecbae334138757fe232c4fb98a01d56f684cb2"

    strings:
        $aes_salt         = { BF EB 1E 56 FB CD 97 3B B2 19 }
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }

        $str_common_msg    = "Quasar.Common.Messages" ascii fullword
        $str_shell_resp    = "DoShellExecuteResponse" wide ascii fullword
        $str_masterkey_err = "masterKey can not be null or empty" wide ascii
        $str_uninstall     = "Uninstalling... good bye :-(" wide
        $str_dont_close    = "echo DONT CLOSE THIS WINDOW!" wide ascii
        $str_new_session   = ">> New Session created" wide ascii
        $str_wan_ip        = "WAN IP Address" wide ascii
        $str_user_refused  = "User refused the elevation request." wide ascii
        $str_bouncy        = "Org.BouncyCastle." wide ascii
        $str_mousekeyhook  = "Gma.System.MouseKeyHook" ascii

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and (
            ( $aes_salt and 2 of ($str_*) )
            or ( $patt_verify_hash and 2 of ($str_*) )
            or 4 of ($str_*)
        )
}