// source: https://github.com/StrangerealIntel/DailyIOC/blob/master/2020-11-24/Mespinoza/Ran_Mespinoza_Nov_2020_1.yar

rule Ran_Mespinoza_Nov_2020_1 {
   meta:
      description = "Detect Mespinoza ransomware"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-11-24"
      score = 70
      hash1 = "e4287e9708a73ce6a9b7a3e7c72462b01f7cc3c595d972cf2984185ac1a3a4a8"
      hash2 = "327934c4c11ba37f42a91e1b7b956d5a4511f918e63047a8c4aa081fd39de6d9"
   strings:
      $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" fullword ascii
      $s2 = "update.bat" fullword ascii
      $s3 = "Crypto++ RNG" fullword ascii
      $s4 = "%s\\Readme.README" fullword wide
      $s5 = "\\System Volume Information\\" fullword wide
      $s6 = ":\\Windows\\" fullword wide
      // ref ransom note
      $s7 = { 48 69 20 43 6f 6d 70 61 6e 79 2c 0d 0a 0d 0a 45 76 65 72 79 20 62 79 74 65 20 6f 6e 20 61 6e 79 20 74 79 70 65 73 20 6f 66 20 79 6f 75 72 20 64 65 76 69 63 65 73 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 2e 0d 0a 44 6f 6e 27 74 20 74 72 79 20 74 6f 20 75 73 65 20 62 61 63 6b 75 70 73 20 62 65 63 61 75 73 65 20 69 74 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 74 6f 6f 2e 0d 0a 0d 0a 54 6f 20 67 65 74 20 61 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 62 61 63 6b 20 63 6f 6e 74 61 63 74 20 75 73 3a }
      $s8 = { 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 0d 0a 0d 0a 46 41 51 3a 0d 0a 0d 0a 31 2e 0d 0a 20 20 20 51 3a 20 48 6f 77 20 63 61 6e 20 49 20 6d 61 6b 65 20 73 75 72 65 20 79 6f 75 20 64 6f 6e 27 74 20 66 6f 6f 6c 69 6e 67 20 6d 65 3f 0d 0a 20 20 20 41 3a 20 59 6f 75 20 63 61 6e 20 73 65 6e 64 20 75 73 20 32 20 66 69 6c 65 73 28 6d 61 78 20 32 6d 62 29 2e 0d 0a 0d 0a 32 2e 0d 0a 20 20 20 51 3a 20 57 68 61 74 20 74 6f 20 64 6f 20 74 6f 20 67 65 74 20 61 6c 6c 20 64 61 74 61 20 62 61 63 6b 3f 0d 0a 20 20 20 41 3a 20 44 6f 6e 27 74 20 72 65 73 74 61 72 74 20 74 68 65 20 63 6f 6d 70 75 74 65 72 2c 20 64 6f 6e 27 74 20 6d 6f 76 65 20 66 69 6c 65 73 20 61 6e 64 20 77 72 69 74 65 20 75 73 2e 0d 0a 0d 0a 33 2e 0d 0a 20 20 20 51 3a 20 57 68 61 74 20 74 6f 20 74 65 6c 6c 20 6d 79 20 62 6f 73 73 3f 0d 0a 20 20 20 41 3a 20 50 72 6f 74 65 63 74 20 59 6f 75 72 20 53 79 73 74 65 6d 20 41 6d 69 67 6f}
      // ref extensions
      $s9 = { 64 00 6f 00 63 00 00 00 00 00 2e 00 78 00 6c 00 73 00 00 00 00 00 2e 00 64 00 6f 00 63 00 78 00 00 00 2e 00 78 00 6c 00 73 00 78 00 00 00 2e 00 70 00 64 00 66 00 00 00 00 00 2e 00 64 00 62 00 00 00 2e 00 64 00 62 00 33 00 00 00 00 00 2e 00 66 00 72 00 6d 00 00 00 00 00 2e 00 69 00 62 00 00 00 2e 00 6d 00 64 00 66 00 00 00 00 00 2e 00 6d 00 77 00 62 00 00 00 00 00 2e 00 6d 00 79 00 64 00 00 00 00 00 2e 00 6e 00 64 00 66 00 00 00 00 00 2e 00 73 00 64 00 66 00 00 00 00 00 2e 00 73 00 71 00 6c 00 00 00 00 00 2e 00 74 00 72 00 63 00 00 00 00 00 2e 00 77 00 72 00 6b 00 00 00 00 00 2e 00 30 00 30 00 31 00 00 00 00 00 2e 00 61 00 63 00 72 00 00 00 00 00 2e 00 62 00 61 00 63 00 00 00 00 00 2e 00 62 00 61 00 6b 00 00 00 00 00 2e 00 62 00 61 00 63 00 6b 00 75 00 70 00 64 00 62 00 00 00 2e 00 62 00 63 00 6b 00 00 00 00 00 2e 00 62 00 6b 00 66 00 00 00 00 00 2e 00 62 00 6b 00 75 00 70 00 00 00 2e 00 62 00 75 00 70 00 00 00 00 00 2e 00 66 00 62 00 6b 00 00 00 00 00 2e 00 6d 00 69 00 67 00 00 00 00 00 2e 00 73 00 70 00 66 00 00 00 00 00 2e 00 76 00 68 00 64 00 78 00 00 00 2e 00 76 00 66 00 64 00 00 00 00 00 2e 00 61 00 76 00 68 00 64 00 78 00 00 00 00 00 2e 00 76 00 6d 00 63 00 78 00 00 00 2e 00 76 00 6d 00 72 00 73 00 00 00 2e 00 70 00 62 00 66 00 00 00 00 00 2e 00 71 00 69 00 63 00 00 00 00 00 2e 00 73 00 71 00 62 00 00 00 00 00 2e 00 74 00 69 00 73 00 00 00 00 00 2e 00 76 00 62 00 6b 00 00 00 00 00 2e 00 76 00 62 00 6d 00 00 00 00 00 2e 00 76 00 72 00 62 00 00 00 00 00 2e 00 77 00 69 00 6e 00 00 00 00 00 2e 00 70 00 73 00 74 00 00 00 00 00 2e 00 6d 00 64 00 62 00 00 00 00 00 2e 00 37 00 7a 00 00 00 2e 00 7a 00 69 00 70 00 00 00 00 00 2e 00 72 00 61 00 72 00 00 00 00 00 2e 00 63 00 61 00 64 00 00 00 00 00 2e 00 64 00 73 00 64 00 00 00 00 00 2e 00 64 00 77 00 67 00 00 00 00 00 2e 00 70 00 6c 00 61 00 00 00 00 00 2e 00 70 00 6c 00 6e 00 00 00 00 00 2e 00 52 00 45 00 41 00 44 00 4d 00 45 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 2e 00 64 00 6c 00 6c }
      $s10 = ".?AV?$TF_EncryptorImpl@U?$TF_CryptoSchemeOptions@V?$TF_ES@URSA@CryptoPP@@V?$OAEP@VSHA1@CryptoPP@@VP1363_MGF1@2@@2@H@CryptoPP@@UR" ascii
      $s11 = ".?AV?$TF_ObjectImpl@VTF_EncryptorBase@CryptoPP@@U?$TF_CryptoSchemeOptions@V?$TF_ES@URSA@CryptoPP@@V?$OAEP@VSHA1@CryptoPP@@VP1363" ascii
      $s12 = " is not a valid key length" fullword ascii
      $s13 = "Timer: QueryPerformanceFrequency failed with error " fullword ascii
      $s14 = " operation failed with error " fullword ascii
   condition:
       uint16(0) == 0x5a4d and filesize > 200KB and 10 of ($s*)
}
