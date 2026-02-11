rule DYNOWIPER {  
    meta: 
        author = "CERT Polska"
        description = "Detects DYNOWIPER data destruction malware"  
        severity = "CRITICAL"  
        reference = "https://mwdb.cert.pl/"  
          
    strings:  
        $a1 = "$recycle.bin" wide  
        $a2 = "program files(x86)" wide  
        $a3 = "perflogs" wide  
        $a4 = "windows\x00" wide  
        $b1 = "Error opening file: " wide  
        $priv = "SeShutdownPrivilege" wide  
        $api1 = "GetLogicalDrives"  
        $api2 = "ExitWindowsEx"  
        $api3 = "AdjustTokenPrivileges"  
          
    condition:  
        uint16(0) == 0x5A4D  
        and filesize < 500KB  
        and 4 of ($a*, $b1)  
        and $priv  
        and 2 of ($api*)  
}
