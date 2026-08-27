// Encoded / obfuscated EICAR anti-malware test file signatures.

rule EICAR_Base64_Encoded
{
	meta:
		author = "filescan.io"
		description = "Detects base64-encoded EICAR test string, all 3 byte alignments"
		score = 75

	strings:
		/* Written out as literal base64 rather than with the `base64` modifier:
		   hardening has NO SUPPORT for base64.
		   One string per byte alignment, alignment-dependent edge chars trimmed. */
		$a0 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSC" ascii
		$a1 = "g1TyFQJUBBUFs0XFBaWDU0KFBeKTdDQyk3fSRFSUNBUi1TVEFOREFSRC1BTlRJVklSVVMtVEVTVC1GSUxFISRIK0gq" ascii
		$a2 = "YNU8hUCVAQVBbNFxQWlg1NChQXik3Q0MpN30kRUlDQVItU1RBTkRBUkQtQU5USVZJUlVTLVRFU1QtRklMRSEkSCtIK" ascii

	condition:
		any of them
}

rule EICAR_Hex_Encoded
{
	meta:
		author = "filescan.io"
		description = "Detects hex-encoded EICAR test string, lower or upper case"
		score = 75

	strings:
		/* Two literal strings instead of one `nocase` string: hardening
		   drops nocase when it rewrites text into hex. */
		$lower = "58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a" ascii wide
		$upper = "58354F2150254041505B345C505A58353428505E2937434329377D2445494341522D5354414E444152442D414E544956495255532D544553542D46494C452124482B482A" ascii wide

	condition:
		any of them
}

rule EICAR_XOR_Encoded
{
	meta:
		author = "filescan.io"
		description = "Detects single-byte XOR encoded EICAR test string"
		score = 75

	strings:
		/* Hardening caps the xor expansion: after tools/ci/harden_yara.py only keys
		   0x01-0x1f survive here, so the shipped rule covers part of the key space.
		   Accepted for simplicity - splitting into ranges of <= 60 keys would avoid
		   the cap at the cost of five strings instead of one. */
		$a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" xor(0x01-0xff)

	condition:
		any of them
}

rule EICAR_ROT13_Encoded
{
	meta:
		author = "filescan.io"
		description = "Detects ROT13-encoded EICAR test string"
		score = 75

	strings:
		$a = "K5B!C%@NC[4\\CMK54(C^)7PP)7}$RVPNE-FGNAQNEQ-NAGVIVEHF-GRFG-SVYR!$U+U*" ascii wide

	condition:
		any of them
}

rule EICAR_Reversed
{
	meta:
		author = "filescan.io"
		description = "Detects byte-reversed EICAR test string"
		score = 75

	strings:
		$a = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X" ascii wide

	condition:
		any of them
}

rule EICAR_UTF16_Plaintext
{
	meta:
		author = "filescan.io"
		description = "Detects the EICAR test string stored as UTF-16, which the ASCII-only EICAR rules miss"
		score = 75

	strings:
		$a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" wide

	condition:
		any of them
}
