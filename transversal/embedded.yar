rule Base64_Embedded_Files
{
    meta:
        description = "Detects potential base64-encoded embedded files"
        author = "OPSWAT"
        score = 60

    strings:
        // Executables
        // PE covered with Base64_encoded_Executable rule
        $b64_ELF = {66 30 56 4d 52 67}

        // ZIP format and others based on it (such as docx, xlsx, apk, etc)
        $b64_ZIP_1 = {55 45 73 44 42 41}
        $b64_ZIP_2 = {55 45 73 46 42 67}
        $b64_ZIP_3 = {55 45 73 48 43 41}

        // Other archives
        $b64_RAR_1 = {55 6d 46 79 49 52 6f 48 41 41}
        $b64_RAR_2 = {55 6d 46 79 49 52 6f 48 41 51 41}
        $b64_7Z = {4e 33 71 38 72 79 63 63}

        // Documents
        $b64_PDF = {4a 56 42 45 52 69 30}
        // Older Office documents and Windows installer
        $b64_CFBF = {30 4d 38 52 34 4b 47 78 47 75 45}

    condition:
        any of them
}