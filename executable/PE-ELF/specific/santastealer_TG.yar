import "pe"

rule santastealer_telegram
{
	meta:
		author = "OPSWAT"
		description = "Detects SantaStealer's telegram channel string"
		score = 75
	strings:
		$SantaStealer_tg = "t.me/SantaStealer"
	condition:
		pe.is_pe and $SantaStealer_tg
}
