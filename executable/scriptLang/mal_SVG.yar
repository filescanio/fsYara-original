rule malicious_SVG_1 {
	meta:
		author = "OPSWAT"
		description = "Identify malicious JavaScript on SVG files"
		score = 75
	strings:
		$tag_xml_header = "<?xml version="
		$tag_svg_start = "<svg"
		$tag_svg_end = "</svg>"

		$tag_script_start = "<script"
		$tag_script_end = "</script"

		$st1_cdata = "<![CDATA["

		$st2_atob = "atob("
		$st2_charcode = "charCodeAt("
		$st2_split = ".split("
		$st2_map = ".map("

	condition:
		all of ($tag*) and $st1_cdata
		and all of ($st2*)
		and for all of ($st*) : ( @ > @tag_script_start and @ < @tag_script_end )

}

rule malicious_SVG_2 {
	// This rule is very similar but needs to be different than _1 since I cannot
	// use the syntax "3 of ($st1*)"" because the loop requires all of them to match
	meta:
		author = "OPSWAT"
		description = "Identify malicious JavaScript on SVG files"
		score = 75
	strings:
		$tag_xml_header = "<?xml version="
		$tag_svg_start = "<svg"
		$tag_svg_end = "</svg>"

		$tag_script_start = "<script"
		$tag_script_end = "</script"

		$st1_cdata = "<![CDATA["

		$st2_atob = "atob("
		$st2_charcode = "charCodeAt("
		$st2_map = ".map("

	condition:
		all of ($tag*) and $st1_cdata
		and not malicious_SVG_1
		and all of ($st2*)
		and for all of ($st*) : ( @ > @tag_script_start and @ < @tag_script_end )
}

rule malicious_SVG_3 {
	meta:
		author = "OPSWAT"
		description = "Identify malicious JavaScript on SVG files"
		score = 75
	strings:
		$tag_svg_start = "<svg"
		$tag_svg_end = "</svg>"

		$tag_script_start = "<script"
		$tag_script_end = "</script"

		$st1_cdata = "<![CDATA["

		$st2_try = "try {"
		$st2_number_array = /= \[((\"|\')\d(\"|\'), ?){10}/
		$st2_window_location = "window.location.href = "

	condition:
		all of ($tag*) and $st1_cdata
		and not malicious_SVG_1
		and not malicious_SVG_2
		and all of ($st2*)
		and for all of ($st*) : ( @ > @tag_script_start and @ < @tag_script_end )
}