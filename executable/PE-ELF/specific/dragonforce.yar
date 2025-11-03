rule DragonForce
{
    meta:
        author = "Idan Malihi"
        created = "08/03/2025"
        description = "Yara Rule for DragonForce Ransomware"
        md5 = "05f13a9c902297debecb4c94c6674c"
        score = 75
        tag = ["dragonforce"]

    strings:
        $mz = { 4D 5A }
        $ChaCha20 = "expand 32-byte k" ascii wide
        $Renaming = "Renaming" ascii wide
        $newName = "New name:" ascii wide
        $processIsElevated = "Process is elevated:" ascii wide nocase
        $shadowCopyWmi = "SELECT * FROM Win32_ShadowCopy" ascii wide
        $ransomFile = "readme.txt" ascii wide nocase
        $decompressProcess = "A7Decompress asset:" ascii wide

    condition:
        $mz at 0 and
        4 of ($ChaCha20, $Renaming, $newName, $processIsElevated, $shadowCopyWmi, $ransomFile, $decompressProcess)
}
