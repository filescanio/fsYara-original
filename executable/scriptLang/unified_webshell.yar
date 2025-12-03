// Consolidated Webshell YARA ruleset
// Version: 1.2
// Sources:
//   - fsYara-original/low_hit/apt_aus_parl_compromise.yar
//   - fsYara-original/low_hit/apt_sandworm_centreon.yar
//   - fsYara-original/low_hit/apt_apt29_grizzly_steppe.yar
//   - fsYara-original/low_hit/expl_spring4shell.yar
//   - fsYara-original/low_hit/expl_proxyshell.yar
//   - fsYara-original/low_hit/apt_webshell_chinachopper.yar
//   - fsYara-original/low_hit/apt_op_wocao.yar
//   - fsYara-original/low_hit/apt_ncsc_report_04_2018.yar
//   - fsYara-original/low_hit/apt_unc2546_dewmode.yar
//   - fsYara-original/low_hit/WShell_ChinaChopper.yar
//   - fsYara-original/low_hit/apt_sandworm_exim_expl.yar
//   - fsYara-original/executable/scriptLang/MALW_Magento_backend.yar
//   - fsYara-original/executable/scriptLang/gen_webshells_ext_vars.yar
//   - fsYara-original/executable/PE-ELF/generic/apt_hafnium.yar
//   - fsYara-original/executable/PE-ELF/specific/apt_solarwinds_sunburst.yar
//   - fsYara-original/executable/PE-ELF/specific/cn_pentestset_tools.yar
//   - fsYara-original/executable/PE-ELF/specific/apt_volatile_cedar.yar
//   - fsYara-original/executable/PE-ELF/specific/indicator_tools.yar
//   - fsYara-original/transversal/APT_Irontiger.yar
//   - fsYara-original/transversal/WShell_PHP_in_images.yar
//   - fsYara-original/transversal/WShell_ASPXSpy.yar
//   - fsYara-original/low_hit/apt_op_cleaver.yar
//   - fsYara-original/executable/scriptLang/gen_webshells.yar
//   - fsYara-original/executable/scriptLang/WShell_THOR_Webshells.yar

// ===== Source: fsYara-original/low_hit/apt_aus_parl_compromise.yar =====

rule APT_WebShell_Tiny_1 {
   meta:
      description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      id = "e65a8920-0684-5aae-a2b8-079c2beae08a"
   strings:
      $x1 = "eval(" ascii wide
   condition:
      ( uint16(0) == 0x3f3c or uint16(0) == 0x253c ) and filesize < 40 and $x1
}


rule APT_WebShell_AUS_Tiny_2 {
   meta:
      description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      hash1 = "0d6209d86f77a0a69451b0f27b476580c14e0cda15fa6a5003aab57a93e7e5a5"
      id = "4746d4ce-628a-59b0-9032-7e0759d96ad3"
   strings:
      $x1 = "Request.Item[System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"[password]\"))];" ascii
      $x2 = "eval(arguments,System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"" ascii
   condition:
      ( uint16(0) == 0x3f3c or uint16(0) == 0x253c ) and filesize < 1KB and 1 of them
}


rule APT_WebShell_AUS_JScript_3 {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      hash1 = "7ac6f973f7fccf8c3d58d766dec4ab7eb6867a487aa71bc11d5f05da9322582d"
      id = "ff7e780b-ccf9-53b6-b741-f04a8cbaf580"
   strings:
      $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\"%><%try{eval(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String" ascii
      $s2 = ".Item[\"[password]\"])),\"unsafe\");}" ascii
   condition:
      uint16(0) == 0x6568 and filesize < 1KB and all of them
}



rule APT_WebShell_AUS_4 {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      hash1 = "83321c02339bb51735fbcd9a80c056bd3b89655f3dc41e5fef07ca46af09bb71"
      id = "bb5b10d1-3528-5361-92fc-8440c65dcda4"
   strings:
      $s1 = "wProxy.Credentials = new System.Net.NetworkCredential(pusr, ppwd);" fullword ascii
      $s2 = "{return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(" ascii
      $s3 = ".Equals('User-Agent', StringComparison.OrdinalIgnoreCase))" ascii
      $s4 = "gen.Emit(System.Reflection.Emit.OpCodes.Ret);" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 10KB and 3 of them
}


rule APT_WebShell_AUS_5 {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      hash1 = "54a17fb257db2d09d61af510753fd5aa00537638a81d0a8762a5645b4ef977e4"
      id = "59b3f6aa-2d3b-54b4-b543-57bd9d981e87"
   strings:
      $a1 = "function DEC(d){return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(d));}" fullword ascii
      $a2 = "function ENC(d){return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(d));}" fullword ascii

      $s1 = "var hash=DEC(Request.Item['" ascii
      $s2 = "Response.Write(ENC(SET_ASS_SUCCESS));" fullword ascii
      $s3 = "hashtable[hash] = assCode;" fullword ascii
      $s4 = "Response.Write(ss);" fullword ascii
      $s5 = "var hashtable = Application[CachePtr];" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 2KB and 4 of them
}

// ===== Source: fsYara-original/low_hit/apt_sandworm_centreon.yar =====

rule WEBSHELL_PAS_webshell {
   meta:
      author = "FR/ANSSI/SDO (modified by Florian Roth)"
      description = "Detects P.A.S. PHP webshell - Based on DHS/FBI JAR-16-2029 (Grizzly  Steppe)"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 70
      id = "862aab77-936e-524c-8669-4f48730f4ed5"
   strings:
      $php = "<?php"
      $strreplace = "(str_replace("
      $md5 = ".substr(md5(strrev($"
      $gzinflate = "gzinflate"
      $cookie = "_COOKIE"
      $isset = "isset"
   condition:
      ( filesize > 20KB and filesize < 200KB ) and
      all of them
}


rule WEBSHELL_PAS_webshell_ZIPArchiveFile {
   meta:
      author = "FR/ANSSI/SDO (modified by Florian Roth)"
      description = "Detects an archive file created by P.A.S. for download operation"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "081cc65b-e51c-59fc-a518-cd986e8ee2f7"
   strings:
      $s1 = "Archive created by P.A.S. v."
   condition:
      $s1
}


rule WEBSHELL_PAS_webshell_PerlNetworkScript {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects PERL scripts created by P.A.S. webshell"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 90
      id = "1625b63f-ead7-5712-92b4-0ce6ecc49fd4"
   strings:
      $pl_start = "#!/usr/bin/perl\n$SIG{'CHLD'}='IGNORE'; use IO::Socket; use FileHandle;"
      $pl_status = "$o=\" [OK]\";$e=\" Error: \""
      $pl_socket = "socket(SOCKET, PF_INET, SOCK_STREAM,$tcp) or die print \"$l$e$!$l"
      $msg1 = "print \"$l OK! I\\'m successful connected.$l\""
      $msg2 = "print \"$l OK! I\\'m accept connection.$l\""
   condition:
      filesize < 6000 and
      ( $pl_start at 0 and all of ($pl*) ) or
      any of ($msg*)
}


rule WEBSHELL_PAS_webshell_SQLDumpFile {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects SQL dump file created by P.A.S. webshell"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 90
      id = "4c26feeb-3031-5c91-9eeb-4b5fe9702e39"
   strings:
      $ = "-- [ SQL Dump created by P.A.S. ] --"
   condition:
      1 of them
}

// ===== Source: fsYara-original/low_hit/apt_apt29_grizzly_steppe.yar =====

rule WebShell_PHP_Web_Kit_v3 {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://github.com/wordfence/grizzly"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "2016/01/01"
      id = "dc5fa2c9-3e1e-594d-be4f-141e1f4915f1"
   strings:
      $php = "<?php $"
      $php2 = "@assert(base64_decode($_REQUEST["

      $s1 = "(str_replace(\"\\n\", '', '"
      $s2 = "(strrev($" ascii
      $s3 = "de'.'code';" ascii
   condition:
      ( ( uint32(0) == 0x68703f3c and $php at 0 ) or $php2 ) and
      filesize > 8KB and filesize < 100KB and
      all of ($s*)
}


rule WebShell_PHP_Web_Kit_v4 {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://github.com/wordfence/grizzly"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "2016/01/01"
      id = "a5f915cd-b9c5-5cd3-b0a2-c15f6124737a"
   strings:
      $php = "<?php $"

      $s1 = "(StR_ReplAcE(\"\\n\",'',"
      $s2 = ";if(PHP_VERSION<'5'){" ascii
      $s3 = "=SuBstr_rePlACe(" ascii
   condition:
      uint32(0) == 0x68703f3c and 
      $php at 0 and
      filesize > 8KB and filesize < 100KB and
      2 of ($s*)
}

// ===== Source: fsYara-original/low_hit/expl_spring4shell.yar =====
rule WEBSHELL_JSP_Nov21_1 {
   meta:
      description = "Detects JSP webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.ic3.gov/Media/News/2021/211117-2.pdf"
      date = "2021-11-23"
      score = 70
      id = "117eed28-c44e-5983-b4c7-b555fc06d923"
   strings:
      $x1 = "request.getParameter(\"pwd\")" ascii
      $x2 = "excuteCmd(request.getParameter(" ascii
      $x3 = "getRuntime().exec (request.getParameter(" ascii
      $x4 = "private static final String PW = \"whoami\"" ascii
   condition:
      filesize < 400KB and 1 of them
}


rule EXPL_POC_SpringCore_0day_Indicators_Mar22_1 {
   meta:
      description = "Detects indicators found after SpringCore exploitation attempts and in the POC script"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/vxunderground/status/1509170582469943303"
      date = "2022-03-30"
      score = 70
      id = "297e4b57-f831-56e0-a391-1ffbc9a4d438"
   strings:
      $x1 = "java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di"
      $x2 = "?pwd=j&cmd=whoami"
      $x3 = ".getParameter(%22pwd%22)"
      $x4 = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7B"
   condition:
      1 of them
}


rule EXPL_POC_SpringCore_0day_Webshell_Mar22_1 {
   meta:
      description = "Detects webshell found after SpringCore exploitation attempts POC script"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/vxunderground/status/1509170582469943303"
      date = "2022-03-30"
      score = 70
      id = "e7047c98-3c60-5211-9ad5-2bfdfb35d493"
   strings:
      $x1 = ".getInputStream(); int a = -1; byte[] b = new byte[2048];"
      $x2 = "if(\"j\".equals(request.getParameter(\"pwd\")"
      $x3 = ".getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();"
   condition:
     filesize < 200KB and 1 of them
}

// ===== Source: fsYara-original/low_hit/expl_proxyshell.yar =====

rule WEBSHELL_ASPX_ProxyShell_Aug21_2 {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST), size and content"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-servers-are-getting-hacked-via-proxyshell-exploits/"
      date = "2021-08-13"
      id = "a351a466-695e-570e-8c7f-9c6c0534839c"
   strings:
      $s1 = "Page Language=" ascii nocase
   condition:
      uint32(0) == 0x4e444221 /* PST header: !BDN */
      and filesize < 2MB
      and $s1
}


rule WEBSHELL_ASPX_ProxyShell_Aug21_3 {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be DER), size and content"
      author = "Max Altgelt"
      reference = "https://twitter.com/gossithedog/status/1429175908905127938?s=12"
      date = "2021-08-23"
      score = 75
      id = "a7bca62b-c8f1-5a38-81df-f3d4582a590b"
   strings:
      $s1 = "Page Language=" ascii nocase
   condition:
      uint16(0) == 0x8230 /* DER start */
      and filesize < 10KB
      and $s1
}


rule WEBSHELL_ASPX_ProxyShell_Sep21_1 { 
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST) and base64 decoded request"
      author = "Tobias Michalski"
      date = "2021-09-17"
      reference = "Internal Research"
      hash = "219468c10d2b9d61a8ae70dc8b6d2824ca8fbe4e53bbd925eeca270fef0fd640"
      score = 75
      id = "d0d23e17-6b6a-51d1-afd9-59cc2404bcd8"
   strings:
      $s = ".FromBase64String(Request["
   condition:
      uint32(0) == 0x4e444221
      and any of them
}


rule WEBSHELL_ASPX_ProxyShell_Exploitation_Aug21_1 {
   meta:
      description = "Detects unknown malicious loaders noticed in August 2021"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/VirITeXplorer/status/1430206853733097473"
      date = "2021-08-25"
      score = 90
      id = "1fa563fc-c91c-5f4e-98f1-b895e1acb4f4"
   strings:
      $x1 = ");eval/*asf" ascii
   condition:
      filesize < 600KB and 1 of them
}


rule WEBSHELL_ASPX_ProxyShell_Aug15 {
   meta:
      description = "Webshells iisstart.aspx and Logout.aspx"
      author = "Moritz Oettle"
      reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
      date = "2021-09-04"
      score = 75
      id = "b1e6c0f3-787f-59b8-8123-4045522047ca"
   strings:
      $g1 = "language=\"JScript\"" ascii
      $g2 = "function getErrorWord" ascii
      $g3 = "errorWord" ascii
      $g4 = "Response.Redirect" ascii
      $g5 = "function Page_Load" ascii
      $g6 = "runat=\"server\"" ascii
      $g7 = "Request[" ascii
      $g8 = "eval/*" ascii

      $s1 = "AppcacheVer" ascii /* HTTP Request Parameter */
      $s2 = "clientCode" ascii /* HTTP Request Parameter */
      $s3 = "LaTkWfI64XeDAXZS6pU1KrsvLAcGH7AZOQXjrFkT816RnFYJQR" ascii
   condition:
      filesize < 1KB and
      ( 1 of ($s*) or 4 of ($g*) )
}


rule WEBSHELL_Mailbox_Export_PST_ProxyShell_Aug26 {
   meta:
      description = "Webshells generated by an Mailbox export to PST and stored as aspx: 570221043.aspx 689193944.aspx luifdecggoqmansn.aspx"
      author = "Moritz Oettle"
      reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
      date = "2021-09-04"
      score = 85
      id = "6aea414f-d27c-5202-84f8-b8620782fc90"
   strings:
      $x1 = "!BDN" /* PST file header */

      $g1 = "Page language=" ascii
      $g2 = "<%@ Page" ascii
      $g3 = "Request.Item[" ascii
      $g4 = "\"unsafe\");" ascii
      $g5 = "<%eval(" ascii
      $g6 = "script language=" ascii
      $g7 = "Request[" ascii

      $s1 = "gold8899" ascii /* HTTP Request Parameter */
      $s2 = "exec_code" ascii /* HTTP Request Parameter */
      $s3 = "orangenb" ascii /* HTTP Request Parameter */
   condition:
      filesize < 500KB and
      $x1 at 0 and
      ( 1 of ($s*) or 3 of ($g*) )
}


rule WEBSHELL_ProxyShell_Exploitation_Nov21_1 {
   meta:
      description = "Detects webshells dropped by DropHell malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.deepinstinct.com/blog/do-not-exchange-it-has-a-shell-inside"
      date = "2021-11-01"
      score = 85
      id = "300eaadf-db0c-5591-84fc-abdf7cdd90c1"
   strings:
      $s01 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Request[" ascii wide
      $s02 = "new System.IO.MemoryStream()" ascii wide
      $s03 = "Transform(" ascii wide
   condition:
      all of ($s*)
}

// ===== Source: fsYara-original/low_hit/apt_webshell_chinachopper.yar =====

rule ChinaChopper_Generic {
	meta:
		description = "China Chopper Webshells - PHP and ASPX"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"
		date = "2015/03/10"
		modified = "2022-10-27"
		id = "2473cef1-88cf-5b76-a87a-2978e6780b4f"
	strings:
		$x_aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(Request\.Item\[.{,100}unsafe/
		$x_php = /<?php.\@eval\(\$_POST./

		$fp1 = "GET /"
		$fp2 = "POST /"
	condition:
		filesize < 300KB and 1 of ($x*) and not 1 of ($fp*)
}

// ===== Source: fsYara-original/low_hit/apt_op_wocao.yar =====

rule APT_MAL_CN_Wocao_webshell_console_jsp {
    meta:
        description = "Strings from the console.jsp webshell"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "1afdfc34-d2e3-58c7-80ea-ee5632e42469"
    strings:
        $a = "String strLogo = request.getParameter(\"image\")"
        $b = "!strLogo.equals(\"web.gif\")"
        $c = "<font color=red>Save Failed!</font>"
        $d = "<font color=red>Save Success!</font>"
        $e = "Save path:<br><input type=text"
        $f = "if (newfile.exists() && newfile.length()>0) { out.println"

    condition:
        1 of them
}


rule APT_MAL_CN_Wocao_webshell_index_jsp {
    meta:
        description = "Strings from the index.jsp socket tunnel"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "9c226ccd-6c69-523c-bca4-371e55274667"
    strings:
        $x1 = "X-CMD"
        $x2 = "X-STATUS"
        $x3 = "X-TARGET"
        $x4 = "X-ERROR"
        $a = "out.print(\"All seems fine.\");"

    condition:
        all of ($x*) and $a
}


rule APT_MAL_CN_Wocao_webshell_ver_jsp {
    meta:
        description = "Strings from the ver.jsp webshell"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "b2828b84-8934-5111-9345-683a07025070"
    strings:
        $a = "String strLogo = request.getParameter(\"id\")"
        $b = "!strLogo.equals(\"256\")"
        $c = "boolean chkos = msg.startsWith"
        $d = "while((c = er.read()) != -1)"
        $e = "out.print((char)c);}in.close()"
        $f = "out.print((char)c);}er.close()"

    condition:
        1 of them
}


rule APT_MAL_CN_Wocao_webshell_webinfo {
    meta:
        description = "Generic strings from webinfo.war webshells"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "b8477f62-f3f6-5526-b0e3-9b794fefaa1f"
    strings:
        $var1 = "String strLogo = request.getParameter"
        $var2 = "String content = request.getParameter(\"content\");"
        $var3 = "String basePath=request.getScheme()"
        $var4 = "!strLogo.equals("
        $var5 = "if(path!=null && !path.equals(\"\") && content!=null"
        $var6 = "File newfile=new File(path);"

        $str1 = "Save Success!"
        $str2 = "Save Failed!"

    condition:
        2 of ($var*) or (all of ($str*) and 1 of ($var*))
}

// ===== Source: fsYara-original/low_hit/apt_ncsc_report_04_2018.yar =====

rule WEBSHELL_Z_WebShell_1 {
   meta:
      author = "NCSC"
      description = "Detects Z Webshell from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      old_rule_name = "Z_WebShell"
      hash = "ace12552f3a980f1eed4cadb02afe1bfb851cafc8e58fb130e1329719a07dbf0"
      id = "f4b50760-bd3a-5e1f-bf32-50f16a42c381"
   strings:
      $ = "Z_PostBackJS" ascii wide
      $ = "z_file_download" ascii wide
      $ = "z_WebShell" ascii wide
      $ = "1367948c7859d6533226042549228228" ascii wide
   condition:
      3 of them
}

// ===== Source: fsYara-original/low_hit/apt_unc2546_dewmode.yar =====

rule WEBSHELL_APT_PHP_DEWMODE_UNC2546_Feb21_1 {
   meta:
      description = "Detects DEWMODE webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2021/02/accellion-fta-exploited-for-data-theft-and-extortion.html"
      date = "2021-02-22"
      hash1 = "2e0df09fa37eabcae645302d9865913b818ee0993199a6d904728f3093ff48c7"
      hash2 = "5fa2b9546770241da7305356d6427847598288290866837626f621d794692c1b"
      id = "ea883f25-0e9b-5617-b05e-191a4a5c5a52"
   strings:
      $x1 = "<font size=4>Cleanup Shell</font></a>';" ascii fullword
      $x2 = "$(sh /tmp/.scr)"
      $x3 = "@system('sudo /usr/local/bin/admin.pl --mount_cifs=" ascii
      
      $s1 = "target=\\\"_blank\\\">Download</a></td>\";" ascii
      $s2 = ",PASSWORD 1>/dev/null 2>/dev/null');" ascii
      $s3 = ",base64_decode('" ascii
      $s4 = "include \"remote.inc\";" ascii
      $s5 = "@system('sudo /usr/local" ascii
   condition:
      uint16(0) == 0x3f3c and
      filesize < 9KB and
      ( 1 of ($x*) or 2 of them ) or 3 of them
}

// ===== Source: fsYara-original/low_hit/WShell_ChinaChopper.yar =====

rule webshell_ChinaChopper_aspx
{
  meta:
    author      = "Ryan Boyle randomrhythm@rhythmengineering.com"
    date        = "2020/10/28"
    description = "Detect China Chopper ASPX webshell"
    reference1  = "https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html"
    filetype    = "aspx"
  strings:
	$ChinaChopperASPX = {25 40 20 50 61 67 65 20 4C 61 6E 67 75 61 67 65 3D ?? 4A 73 63 72 69 70 74 ?? 25 3E 3C 25 65 76 61 6C 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-100] 75 6E 73 61 66 65}
  condition:
	$ChinaChopperASPX
}


rule webshell_ChinaChopper_php
{
  meta:
    author      = "Ryan Boyle randomrhythm@rhythmengineering.com"
    date        = "2020/10/29"
    description = "Detect China Chopper PHP webshell"
    reference1  = "https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html"
    filetype    = "php"
  strings:
	$ChinaChopperPHP = {3C 3F 70 68 70 20 40 65 76 61 6C 28 24 5F 50 4F 53 54 5B ?? 70 61 73 73 77 6F 72 64 ?? 5D 29 3B 3F 3E}
  condition:
	$ChinaChopperPHP
}

// ===== Source: fsYara-original/low_hit/apt_sandworm_exim_expl.yar =====

rule APT_WEBSHELL_PHP_Sandworm_May20_1 {
   meta:
      description = "Detects GIF header PHP webshell used by Sandworm on compromised machines"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      id = "b9ec02c2-fa83-5f21-95cf-3528047b2d01"
   strings:     
      $h1 = "GIF89a <?php $" ascii
      $s1 = "str_replace(" ascii
   condition:
      filesize < 10KB and
      $h1 at 0 and $s1
}

// ===== Source: fsYara-original/executable/scriptLang/MALW_Magento_backend.yar =====
rule fopo_webshell {
    strings:
        $ = "DNEcHdQbWtXU3dSMDA1VmZ1c29WUVFXdUhPT0xYb0k3ZDJyWmFVZlF5Y0ZEeHV4K2FnVmY0OUtjbzhnc0"
        $ = "U3hkTVVibSt2MTgyRjY0VmZlQWo3d1VlaFJVNVNnSGZUVUhKZXdEbGxJUTlXWWlqWSt0cEtacUZOSXF4c"
        $ = "rb2JHaTJVdURMNlhQZ1ZlTGVjVnFobVdnMk5nbDlvbEdBQVZKRzJ1WmZUSjdVOWNwWURZYlZ0L1BtNCt"
    condition: any of them
}

// ===== Source: fsYara-original/executable/PE-ELF/generic/apt_hafnium.yar =====
rule WEBSHELL_ASP_Embedded_Mar21_1 {
   meta:
      description = "Detects ASP webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-03-05"
      score = 85
      id = "7cf7db9d-8f8a-51db-a0e6-84748e8f9e1f"
   strings:
      $s1 = "<script runat=\"server\">" nocase
      $s2 = "new System.IO.StreamWriter(Request.Form["
      $s3 = ".Write(Request.Form["
   condition:
      filesize < 100KB and all of them
}


rule APT_WEBSHELL_HAFNIUM_SecChecker_Mar21_1 {
   meta:
      description = "Detects HAFNIUM SecChecker webshell"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/markus_neis/status/1367794681237667840"
      date = "2021-03-05"
      hash1 = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"
      id = "73db3d78-7ece-53be-9efb-d19801993d5e"
   strings:
      $x1 = "<%if(System.IO.File.Exists(\"c:\\\\program files (x86)\\\\fireeye\\\\xagt.exe" ascii
      $x2 = "\\csfalconservice.exe\")){Response.Write( \"3\");}%></head>" ascii fullword
   condition:
      uint16(0) == 0x253c and
      filesize < 1KB and
      1 of them or 2 of them
}


rule APT_WEBSHELL_HAFNIUM_Chopper_WebShell: APT Hafnium WebShell {
   meta:
      description = "Detects Chopper WebShell Injection Variant (not only Hafnium related)"
      author = "Markus Neis,Swisscom"
      date = "2021-03-05"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      id = "25dcf166-4aea-5680-b161-c5fc8d74b987"
   strings:
      $x1 = "runat=\"server\">" nocase

      $s1 = "<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request" nocase
      $s2 = "protected void Page_Load(object sender, EventArgs e){System.IO.StreamWriter sw = new System.IO.StreamWriter(Request.Form[\"p\"] , false, Encoding.Default);sw.Write(Request.Form[\"f\"]);"
      $s3 = "<script language=\"JScript\" runat=\"server\"> function Page_Load(){eval (Request[\"" nocase
   condition:
      filesize < 10KB and $x1 and 1 of ($s*)
}


rule APT_WEBSHELL_Tiny_WebShell : APT Hafnium WebShell {
   meta:
      description = "Detects WebShell Injection"
      author = "Markus Neis,Swisscom"
      hash = "099c8625c58b315b6c11f5baeb859f4c"
      date = "2021-03-05"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      id = "aa2fcecc-4c8b-570d-a81a-5dfb16c04e05"
   strings:
      $x1 = "<%@ Page Language=\"Jscript\" Debug=true%>"

      $s1 = "=Request.Form(\""
      $s2 = "eval("
   condition:
      filesize < 300 and all of ($s*) and $x1
}


rule WEBSHELL_ASPX_SimpleSeeSharp : Webshell Unclassified {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-03-01"
      description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
      hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      id = "469fdf5c-e09e-5d44-a2e6-0864dcd0e18a"
   strings:
      $header = "<%@ Page Language=\"C#\" %>"
      $body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"
   condition:
      $header at 0 and
      $body and
      filesize < 1KB
}


rule WEBSHELL_ASPX_reGeorgTunnel : Webshell Commodity {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-03-01"
      description = "variation on reGeorgtunnel"
      hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
      reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
      id = "b8aa27c9-a28a-5051-8f81-1184f28842ed"
   strings:
      $s1 = "System.Net.Sockets"
      $s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"
      $t1 = ".Split('|')"
      $t2 = "Request.Headers.Get"
      $t3 = ".Substring("
      $t4 = "new Socket("
      $t5 = "IPAddress ip;"
   condition:
      all of ($s*) or
      all of ($t*)
}


rule WEBSHELL_ASPX_SportsBall {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-03-01"
      description = "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
      hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      id = "25b23a4c-8fc7-5d6f-b4b5-46fe2c1546d8"
   strings:
      $uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
      $uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="

      $var1 = "Result.InnerText = string.Empty;"
      $var2 = "newcook.Expires = DateTime.Now.AddDays("
      $var3 = "System.Diagnostics.Process process = new System.Diagnostics.Process();"
      $var4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
      $var5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
      $var6 = "<input type=\"submit\" value=\"Upload\" />"
   condition:
      any of ($uniq*) or
      all of ($var*)
}


rule WEBSHELL_CVE_2021_27065_Webshells {
   meta:
      description = "Detects web shells dropped by CVE-2021-27065. All actors, not specific to HAFNIUM. TLP:WHITE"
      author = "Joe Hannon, Microsoft Threat Intelligence Center (MSTIC)"
      date = "2021-03-05"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      id = "27677f35-24a3-59cc-a3ad-b83884128da7"
   strings:
      $script1 = "script language" ascii wide nocase
      $script2 = "page language" ascii wide nocase
      $script3 = "runat=\"server\"" ascii wide nocase
      $script4 = "/script" ascii wide nocase
      $externalurl = "externalurl" ascii wide nocase
      $internalurl = "internalurl" ascii wide nocase
      $internalauthenticationmethods = "internalauthenticationmethods" ascii wide nocase
      $extendedprotectiontokenchecking = "extendedprotectiontokenchecking" ascii wide nocase
   condition:
      filesize < 50KB and any of ($script*) and ($externalurl or $internalurl) and $internalauthenticationmethods and $extendedprotectiontokenchecking
}


rule WEBSHELL_Compiled_Webshell_Mar2021_1 {
   meta:
      description = "Triggers on temporary pe files containing strings commonly used in webshells."
      author = "Bundesamt fuer Sicherheit in der Informationstechnik"
      date = "2021-03-05"
      modified = "2021-03-12"
      reference = "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/Vorfaelle/Exchange-Schwachstellen-2021/MSExchange_Schwachstelle_Detektion_Reaktion.pdf"
      id = "9336bd2c-791c-5c3e-9733-724a6a23864a"
   strings:
      $x1 = /App_Web_[a-zA-Z0-9]{7,8}.dll/ ascii wide fullword
      $a1 = "~/aspnet_client/" ascii wide nocase
      $a2 = "~/auth/" ascii wide nocase
      $b1 = "JScriptEvaluate" ascii wide fullword
      $c1 = "get_Request" ascii wide fullword
      $c2 = "get_Files" ascii wide fullword
      $c3 = "get_Count" ascii wide fullword
      $c4 = "get_Item" ascii wide fullword
      $c5 = "get_Server" ascii wide fullword
   condition:
      uint16(0) == 0x5a4d and filesize > 5KB and filesize < 40KB and all of ($x*) and 1 of ($a*) and ( all of ($b*) or all of ($c*) )
}



rule WEBSHELL_HAFNIUM_CISA_10328929_01 : trojan webshell exploit CVE_2021_27065 {
   meta:
       author = "CISA Code & Media Analysis"
       date = "2021-03-17"
       description = "Detects CVE-2021-27065 Webshellz"
       hash = "c8a7b5ffcf23c7a334bb093dda19635ec06ca81f6196325bb2d811716c90f3c5"
       reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar21-084a"
       id = "81916396-8aaa-5045-b31c-4bcce8d295a5"
   strings:
       $s0 = { 65 76 61 6C 28 52 65 71 75 65 73 74 5B 22 [1-32] 5D 2C 22 75 6E 73 61 66 65 22 29 }
       $s1 = { 65 76 61 6C 28 }
       $s2 = { 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-36] 5D 29 29 2C 22 75 6E 73 61 66 65 22 29 }
       $s3 = { 49 4F 2E 53 74 72 65 61 6D 57 72 69 74 65 72 28 52 65 71 75 65 73 74 2E 46 6F 72 6D 5B [1-24] 5D }
       $s4 = { 57 72 69 74 65 28 52 65 71 75 65 73 74 2E 46 6F 72 6D 5B [1-24] 5D }
   condition:
       $s0 or ($s1 and $s2) or ($s3 and $s4)
}


rule WEBSHELL_HAFNIUM_CISA_10328929_02 : trojan webshell exploit CVE_2021_27065 {
   meta:
       author = "CISA Code & Media Analysis"
       date = "2021-03-17"
       description = "Detects CVE-2021-27065 Exchange OAB VD MOD"
       hash = "c8a7b5ffcf23c7a334bb093dda19635ec06ca81f6196325bb2d811716c90f3c5"
       reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar21-084a"
       id = "34a89a6e-fa8a-5c64-a325-30202e20b30f"
   strings:
       $s0 = { 4F 66 66 6C 69 6E 65 41 64 64 72 65 73 73 42 6F 6F 6B 73 }
       $s1 = { 3A 20 68 74 74 70 3A 2F 2F [1] 2F }
       $s2 = { 45 78 74 65 72 6E 61 6C 55 72 6C 20 20 20 20 }
   condition:
       $s0 and $s1 and $s2
}



rule WEBSHELL_ASPX_FileExplorer_Mar21_1 {
   meta:
      description = "Detects Chopper like ASPX Webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-03-31"
      score = 80
      hash1 = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
      id = "edcaa2a8-6fea-584e-90c2-307a2dfc9f7f"
   strings:
      $x1 = "<span style=\"background-color: #778899; color: #fff; padding: 5px; cursor: pointer\" onclick=" ascii
      $xc1 = { 3C 61 73 70 3A 48 69 64 64 65 6E 46 69 65 6C 64
               20 72 75 6E 61 74 3D 22 73 65 72 76 65 72 22 20
               49 44 3D 22 ?? ?? ?? ?? ?? 22 20 2F 3E 3C 62 72
               20 2F 3E 3C 62 72 20 2F 3E 20 50 72 6F 63 65 73
               73 20 4E 61 6D 65 3A 3C 61 73 70 3A 54 65 78 74
               42 6F 78 20 49 44 3D }
      $xc2 = { 22 3E 43 6F 6D 6D 61 6E 64 3C 2F 6C 61 62 65 6C
               3E 3C 69 6E 70 75 74 20 69 64 3D 22 ?? ?? ?? ??
               ?? 22 20 74 79 70 65 3D 22 72 61 64 69 6F 22 20
               6E 61 6D 65 3D 22 74 61 62 73 22 3E 3C 6C 61 62
               65 6C 20 66 6F 72 3D 22 ?? ?? ?? ?? ?? 22 3E 46
               69 6C 65 20 45 78 70 6C 6F 72 65 72 3C 2F 6C 61
               62 65 6C 3E 3C 25 2D 2D }

      $r1 = "(Request.Form[" ascii
      $s1 = ".Text + \" Created!\";" ascii
      $s2 = "DriveInfo.GetDrives()" ascii
      $s3 = "Encoding.UTF8.GetString(FromBase64String(str.Replace(" ascii
      $s4 = "encodeURIComponent(btoa(String.fromCharCode.apply(null, new Uint8Array(bytes))));;"
   condition:
      uint16(0) == 0x253c and
      filesize < 100KB and
      ( 1 of ($x*) or 2 of them ) or 4 of them
}


rule WEBSHELL_ASPX_Chopper_Like_Mar21_1 {
   meta:
      description = "Detects Chopper like ASPX Webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-03-31"
      score = 85
      hash1 = "ac44513e5ef93d8cbc17219350682c2246af6d5eb85c1b4302141d94c3b06c90"
      id = "a4dc1880-865f-5e20-89a2-3a642c453ef9"
   strings:
      $s1 = "http://f/<script language=\"JScript\" runat=\"server\">var _0x" ascii
      $s2 = "));function Page_Load(){var _0x" ascii
      $s3 = ";eval(Request[_0x" ascii
      $s4 = "','orange','unsafe','" ascii
   condition:
      filesize < 3KB and
      1 of them or 2 of them
}

// ===== Source: fsYara-original/executable/PE-ELF/specific/apt_solarwinds_sunburst.yar =====
import "pe"
rule APT_Webshell_SUPERNOVA_1
{
    meta:
        author = "FireEye"
        description = "SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args). This rule is looking for specific strings and attributes related to SUPERNOVA."
        reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
        date = "2020-12-14"
        score = 85
        id = "73a27fa2-a846-5f4b-8182-064ac06c71a8"
    strings:
        $compile1 = "CompileAssemblyFromSource"
        $compile2 = "CreateCompiler"
        $context = "ProcessRequest"
        $httpmodule = "IHttpHandler" ascii
        $string1 = "clazz"
        $string2 = "//NetPerfMon//images//NoLogo.gif" wide
        $string3 = "SolarWinds" ascii nocase wide
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10KB and pe.imports("mscoree.dll","_CorDllMain") and $httpmodule and $context and all of ($compile*) and all of ($string*)
}

rule APT_Webshell_SUPERNOVA_2
{
    meta:
        author = "FireEye"
        description = "This rule is looking for specific strings related to SUPERNOVA. SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args)."
        reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
        date = "2020-12-14"
        score = 85
        id = "c39bf9ba-fd62-5619-92b6-1633375ef197"
    strings:
        $dynamic = "DynamicRun"
        $solar = "Solarwinds" nocase
        $string1 = "codes"
        $string2 = "clazz"
        $string3 = "method"
        $string4 = "args"
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10KB and 3 of ($string*) and $dynamic and $solar
}

// ===== Source: fsYara-original/executable/PE-ELF/specific/cn_pentestset_tools.yar =====

rule CN_Honker_Webshell {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Webshell.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c85bd09d241c2a75b4e4301091aa11ddd5ad6d59"
		id = "12870766-2b85-522d-9ad8-abba2786caaf"
	strings:
		$s1 = "Windows NT users: Please note that having the WinIce/SoftIce" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Do you want to cancel the file download?" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Downloading: %s" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 381KB and all of them
}


rule CN_Honker_GetWebShell {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetWebShell.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b63b53259260a7a316932c0a4b643862f65ee9f8"
		id = "919883f4-af66-5d07-ad41-8cba3e049396"
	strings:
		$s0 = "echo P.Open \"GET\",\"http://www.baidu.com/ma.exe\",0 >>run.vbs" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "http://127.0.0.1/sql.asp?id=1" fullword wide /* PEStudio Blacklist: strings */
		$s14 = "net user admin$ hack /add" fullword wide /* PEStudio Blacklist: strings */
		$s15 = ";Drop table [hack];create table [dbo].[hack] ([cmd] [image])--" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and 1 of them
}


rule CN_Honker_Tuoku_script_oracle_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file oracle.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "865dd591b552787eda18ee0ab604509bae18c197"
		id = "b88a0faa-1616-5f1b-80dc-6e6a2f0cb671"
	strings:
		$s0 = "webshell" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "Silic Group Hacker Army " fullword ascii
	condition:
		filesize < 3KB and all of them
}


rule CN_Honker_net_packet_capt {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file net_packet_capt.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2d45a2bd9e74cf14c1d93fff90c2b0665f109c52"
		id = "16e19be7-3805-5e2b-baa6-20554fb7a5cf"
	strings:
		$s1 = "(*.sfd)" fullword ascii
		$s2 = "GetLaBA" fullword ascii
		$s3 = "GAIsProcessorFeature" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 1 times */
		$s4 = "- Gablto " ascii
		$s5 = "PaneWyedit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}

// ===== Source: fsYara-original/executable/PE-ELF/specific/apt_volatile_cedar.yar =====

rule Webshell_Caterpillar_ASPX {
	meta:
		description = "Volatile Cedar Webshell - from file caterpillar.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/emons5"
		date = "2015/04/03"
		super_rule = 1
		hash0 = "af4c99208fb92dc42bc98c4f96c3536ec8f3fe56"
		id = "9af48c64-3768-5765-8245-38df000598a7"
	strings:
		$s0 = "Dim objNewRequest As WebRequest = HttpWebRequest.Create(sURL)" fullword
		$s1 = "command = \"ipconfig /all\"" fullword
		$s3 = "For Each xfile In mydir.GetFiles()" fullword
		$s6 = "Dim oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
		$s10 = "recResult = adoConn.Execute(strQuery)" fullword
		$s12 = "b = Request.QueryString(\"src\")" fullword
		$s13 = "rw(\"<a href='\" + link + \"' target='\" + target + \"'>\" + title + \"</a>\")" fullword
	condition:
		all of them
}

// ===== Source: fsYara-original/executable/PE-ELF/specific/indicator_tools.yar =====

rule INDICATOR_TOOL_OwlProxy {
    meta:
        author = "ditekSHen"
        description = "Hunt for OwlProxy"
    strings:
        $is1 = "call_new command: " wide
        $is2 = "call_proxy cmd: " wide
        $is3 = "download_file: " wide
        $is4 = "cmdhttp_run" wide
        $is5 = "sub_proxyhttp_run" wide
        $is6 = "proxyhttp_run" wide
        $is7 = "webshell_run" wide
        $is8 = "/exchangetopicservices/" fullword wide
        $is9 = "c:\\windows\\system32\\wmipd.dll" fullword wide
        $iu1 = "%s://+:%d%s" wide
        $iu2 = "%s://+:%d%spp/" wide
        $iu3 = "%s://+:%d%spx/" wide
    condition:
        uint16(0) == 0x5a4d and 6 of ($is*) or (all of ($iu*) and 2 of ($is*))
}

// ===== Source: fsYara-original/transversal/APT_Irontiger.yar =====

rule IronPanda_Webshell_JSP 
{

    meta:
        description = "Iron Panda Malware JSP"
        author = "Florian Roth"
        reference = "https://goo.gl/E4qia9"
        date = "2015-09-16"
        hash = "3be95477e1d9f3877b4355cff3fbcdd3589bb7f6349fd4ba6451e1e9d32b7fa6"
  
    strings:
        $s1 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
        $s2 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
        $s3 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
  
    condition:
        filesize < 330KB and 1 of them
}

// ===== Source: fsYara-original/transversal/WShell_ASPXSpy.yar =====

rule Backdoor_WebShell_asp : ASPXSpy
{
    meta:
      description= "Detect ASPXSpy"
      author = "xylitol@temari.fr"
      date = "2019-02-26"
      score = 75
      // May only the challenge guide you
    strings:
      $string1 = "CmdShell" wide ascii
      $string2 = "ADSViewer" wide ascii
      $string3 = "ASPXSpy.Bin" wide ascii
      $string4 = "PortScan" wide ascii
      $plugin = "Test.AspxSpyPlugins" wide ascii
 
    condition:
    3 of ($string*) or $plugin
}

// ===== Source: fsYara-original/low_hit/apt_op_cleaver.yar =====

rule OPCLEAVER_ShellCreator2
{
	meta:
		description = "Shell Creator used by attackers in Operation Cleaver to create ASPX web shells"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "b62336c3-39e5-55f8-98df-6c2a2cb0764a"
	strings:
		$s1 = "ShellCreator2.Properties"
		$s2 = "set_IV"
	condition:
		all of them
}

// ===== Source: fsYara-original/transversal/WShell_PHP_in_images.yar =====

/*
    Finds PHP code in JP(E)Gs, GIFs, PNGs.
    Magic numbers via Wikipedia.
*/
rule php_in_image
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Finds image files w/ PHP code in images"
        score = 60
    strings:
        $gif = /^GIF8[79]a/
        $jfif = { ff d8 ff e? 00 10 4a 46 49 46 }
        $png = { 89 50 4e 47 0d 0a 1a 0a }

        $php_tag = "<?php"
    condition:
        (($gif at 0) or
        ($jfif at 0) or
        ($png at 0)) and

        $php_tag
}

// ===== Source: fsYara-original/executable/scriptLang/gen_webshells.yar =====
// source:https://github.com/Neo23x0/signature-base/blob/master/yara/gen_webshells.yar

import "math"
// only needed for debugging of module math:
//import "console"

/*

Webshell rules by Arnim Rupp (https://github.com/ruppde), Version 2

Rationale behind the rules:
1. a webshell must always execute some kind of payload (in $payload*). the payload is either:
-- direct php function like exec, file write, sql, ...
-- indirect via eval, self defined functions, callbacks, reflection, ...
2. a webshell must always have some way to get the attackers input, e.g. for PHP in $_GET, php://input or $_SERVER (HTTP for headers).

The input may be hidden in obfuscated code, so we look for either:
a) payload + input
b) eval-style-payloads + obfuscation
c) includers (webshell is split in 2+ files)
d) unique strings, if the coder doesn't even intend to hide

Additional conditions will be added to reduce false positves. Check all findings for unintentional webshells aka vulnerabilities ;)

The rules named "suspicious_" are commented by default. uncomment them to find more potentially malicious files at the price of more false positives. if that finds too many results to manually check, you can compare the hashes to virustotal with e.g. https://github.com/Neo23x0/munin

Some samples in the collection were UTF-16 and at least PHP and Java support it, so I use "wide ascii" for all strings. The performance impact is 1%. See also https://thibaud-robin.fr/articles/bypass-filter-upload/

Rules tested on the following webshell repos and collections:
    https://github.com/sensepost/reGeorg
    https://github.com/WhiteWinterWolf/wwwolf-php-webshell
    https://github.com/k8gege/Ladon
    https://github.com/x-o-r-r-o/PHP-Webshells-Collection
    https://github.com/mIcHyAmRaNe/wso-webshell
    https://github.com/LandGrey/webshell-detect-bypass
    https://github.com/threedr3am/JSP-Webshells
    https://github.com/02bx/webshell-venom
    https://github.com/pureqh/webshell
    https://github.com/secwiki/webshell-2
    https://github.com/zhaojh329/rtty
    https://github.com/modux/ShortShells
    https://github.com/epinna/weevely3
    https://github.com/chrisallenlane/novahot
    https://github.com/malwares/WebShell
    https://github.com/tanjiti/webshellSample
    https://github.com/L-codes/Neo-reGeorg
    https://github.com/bayufedra/Tiny-PHP-Webshell
    https://github.com/b374k/b374k
    https://github.com/wireghoul/htshells
    https://github.com/securityriskadvisors/cmd.jsp
    https://github.com/WangYihang/Webshell-Sniper
    https://github.com/Macr0phag3/WebShells
    https://github.com/s0md3v/nano
    https://github.com/JohnTroony/php-webshells
    https://github.com/linuxsec/indoxploit-shell
    https://github.com/hayasec/reGeorg-Weblogic
    https://github.com/nil0x42/phpsploit
    https://github.com/mperlet/pomsky
    https://github.com/FunnyWolf/pystinger
    https://github.com/tanjiti/webshellsample
    https://github.com/lcatro/php-webshell-bypass-waf
    https://github.com/zhzyker/exphub
    https://github.com/dotcppfile/daws
    https://github.com/lcatro/PHP-WebShell-Bypass-WAF
    https://github.com/ysrc/webshell-sample
    https://github.com/JoyChou93/webshell
    https://github.com/k4mpr3t/b4tm4n
    https://github.com/mas1337/webshell
    https://github.com/tengzhangchao/pycmd
    https://github.com/bartblaze/PHP-backdoors
    https://github.com/antonioCoco/SharPyShell
    https://github.com/xl7dev/WebShell
    https://github.com/BlackArch/webshells
    https://github.com/sqlmapproject/sqlmap
    https://github.com/Smaash/quasibot
    https://github.com/tennc/webshell

Webshells in these repos after fdupes run: 4722
Old signature-base rules found: 1315
This rules found: 3286
False positives in 8gb of common webapps plus yara-ci: 2

*/

rule WEBSHELL_PHP_Generic
{
    meta:
        description = "php webshell having some kind of input and some kind of payload. restricted to small files or big ones inclusing suspicious strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/14"
        modified = "2023-09-18"
        hash = "bee1b76b1455105d4bfe2f45191071cf05e83a309ae9defcf759248ca9bceddd"
        hash = "6bf351900a408120bee3fc6ea39905c6a35fe6efcf35d0a783ee92062e63a854"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "00813155bf7f5eb441e1619616a5f6b21ae31afc99caa000c4aafd54b46c3597"
        hash = "e31788042d9cdeffcb279533b5a7359b3beb1144f39bacdd3acdef6e9b4aff25"
        hash = "36b91575a08cf40d4782e5aebcec2894144f1e236a102edda2416bc75cbac8dd"
        hash = "a34154af7c0d7157285cfa498734cfb77662edadb1a10892eb7f7e2fb5e2486c"
        hash = "791a882af2cea0aa8b8379791b401bebc235296858266ddb7f881c8923b7ea61"
        hash = "9a8ab3c225076a26309230d7eac7681f85b271d2db22bf5a190adbf66faca2e6"
        hash = "0d3ee83adc9ebf8fb1a8c449eed5547ee5e67e9a416cce25592e80963198ae23"
        hash = "3d8708609562a27634df5094713154d8ca784dbe89738e63951e12184ff07ad6"
        hash = "70d64d987f0d9ab46514abcc868505d95dbf458387f858b0d7580e4ee8573786"
        hash = "259b3828694b4d256764d7d01b0f0f36ca0526d5ee75e134c6a754d2ab0d1caa"
        hash = "04d139b48d59fa2ef24fb9347b74fa317cb05bd8b7389aeb0a4d458c49ea7540"
        hash = "58d0e2ff61301fe0c176b51430850239d3278c7caf56310d202e0cdbdde9ac3f"
        hash = "731f36a08b0e63c63b3a2a457667dfc34aa7ff3a2aee24e60a8d16b83ad44ce2"
        hash = "e4ffd4ec67762fe00bb8bd9fbff78cffefdb96c16fe7551b5505d319a90fa18f"
        hash = "fa00ee25bfb3908808a7c6e8b2423c681d7c52de2deb30cbaea2ee09a635b7d4"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "e9423ad8e51895db0e8422750c61ef4897b3be4292b36dba67d42de99e714bff"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "3de8c04bfdb24185a07f198464fcdd56bb643e1d08199a26acee51435ff0a99f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "a09dcf52da767815f29f66cb7b03f3d8c102da5cf7b69567928961c389eac11f"
        hash = "d9ae762b011216e520ebe4b7abcac615c61318a8195601526cfa11bbc719a8f1"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"

        id = "294ce5d5-55b2-5c79-b0f8-b66f949efbb2"
    strings:
        $wfp_tiny1 = "escapeshellarg" fullword
        $wfp_tiny2 = "addslashes" fullword

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword
        //$gfp_tiny2 = "escapeshellarg" fullword
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        $inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii
        $inp20 = "TSOP_" wide ascii
        $inp21 = /file_get_contents\(\$/ wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
        $cpayload23 = /\bReflectionClass[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
        $gen_bit_sus75 = "uploaded" fullword wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "str_rot13" fullword wide ascii

        $gif = { 47 49 46 38 }


        //strings from private rule capa_php_payload_multiple
        // \([^)] to avoid matching on e.g. eval() in comments
        $cmpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
        $cmpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
        $cmpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
        $cmpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
        $cmpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
        $cmpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
        $cmpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
        $cmpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
        $cmpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
        $cmpayload10 = /\bpreg_replace[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
        $cmpayload11 = /\bpreg_filter[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
        $cmpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cmpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
        $cmpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii

        $fp1 = "# Some examples from obfuscated malware:" ascii
        $fp2 = "{@see TFileUpload} for further details." ascii
    condition:
        //any of them or
        not (
            any of ( $gfp_tiny* )
            or 1 of ($fp*)
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and
        (
            ( filesize < 1000 and not any of ( $wfp_tiny* ) )
            or
            (
                (
                    $gif at 0 or
                    (
                        filesize < 4KB and
                        (
                            1 of ( $gen_much_sus* ) or
                            2 of ( $gen_bit_sus* )
                        )
                    ) or (
                        filesize < 20KB and
                        (
                            2 of ( $gen_much_sus* ) or
                            3 of ( $gen_bit_sus* )
                        )
                    ) or (
                        filesize < 50KB and
                        (
                            2 of ( $gen_much_sus* ) or
                            4 of ( $gen_bit_sus* )
                        )
                    ) or (
                        filesize < 100KB and
                        (
                            2 of ( $gen_much_sus* ) or
                            6 of ( $gen_bit_sus* )
                        )
                    ) or (
                        filesize < 150KB and
                        (
                            3 of ( $gen_much_sus* ) or
                            7 of ( $gen_bit_sus* )
                        )
                    ) or (
                        filesize < 500KB and
                        (
                            4 of ( $gen_much_sus* ) or
                            8 of ( $gen_bit_sus* )
                        )
                    )
                )
                and
                ( filesize > 5KB or not any of ( $wfp_tiny* ))
            ) or
                ( filesize < 500KB and (4 of ( $cmpayload* ))
            ) or 
                ( filesize < 5000KB and (8 of ( $cmpayload* )))
        )
}

rule WEBSHELL_PHP_Generic_Callback
{
    meta:
        description = "php webshell having some kind of input and using a callback to execute the payload. restricted to small files or would give lots of false positives"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/14"
        modified = "2023-09-18"
        score = 60
        hash = "e98889690101b59260e871c49263314526f2093f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "81388c8cc99353cdb42572bb88df7d3bd70eefc748c2fa4224b6074aa8d7e6a2"
        hash = "27d3bfabc283d851b0785199da8b1b0384afcb996fa9217687274dd56a7b5f49"
        hash = "ee256d7cc3ceb2bf3a1934d553cdd36e3fbde62a02b20a1b748a74e85d4dbd33"
        hash = "4adc6c5373c4db7b8ed1e7e6df10a3b2ce5e128818bb4162d502056677c6f54a"
        hash = "1fe4c60ea3f32819a98b1725581ac912d0f90d497e63ad81ccf258aeec59fee3"
        hash = "2967f38c26b131f00276bcc21227e54ee6a71881da1d27ec5157d83c4c9d4f51"
        hash = "1ba02fb573a06d5274e30b2b05573305294497769414e964a097acb5c352fb92"
        hash = "f4fe8e3b2c39090ca971a8e61194fdb83d76fadbbace4c5eb15e333df61ce2a4"
        hash = "badda1053e169fea055f5edceae962e500842ad15a5d31968a0a89cf28d89e91"
        hash = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "de1ef827bcd3100a259f29730cb06f7878220a7c02cee0ebfc9090753d2237a8"
        hash = "487e8c08e85774dfd1f5e744050c08eb7d01c6877f7d03d7963187748339e8c4"

        id = "e33dba84-bbeb-5955-a81b-2d2c8637fb48"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword
        //$gfp_tiny2 = "escapeshellarg" fullword
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

        // TODO: arraywalk \n /*
        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback3 = /\barray_diff_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback4 = /\barray_filter[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback7 = /\barray_map[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback8 = /\barray_reduce[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback11 = /\barray_udiff[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback14 = /\barray_uintersect[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback15 = /\barray_walk_recursive[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback16 = /\barray_walk[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback17 = /\bassert_options[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback18 = /\buasort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback19 = /\buksort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback20 = /\busort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback22 = /\bspl_autoload_register[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback23 = /\biterator_apply[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback24 = /\bcall_user_func[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback25 = /\bcall_user_func_array[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback27 = /\bregister_tick_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback28 = /\bset_error_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback29 = /\bset_exception_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback32 = /\bsqlite_create_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii

        $m_callback1 = /\bfilter_var[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
        $cfp3 = "<?phpclass WPML" ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
        $gen_much_sus93 = "eval(\"/*" wide ascii
        $gen_much_sus94 = "http_response_code(404)" wide ascii

        $gif = { 47 49 46 38 }


    condition:
        //any of them or
        not (
            any of ( $gfp* )
        )
        and not (
            any of ( $gfp_tiny* )
        )
        and (
            any of ( $inp* )
        )
        and (
            not any of ( $cfp* ) and
                (
                    any of ( $callback* )  or
                    all of ( $m_callback* )
                )
            )
            and
            ( filesize < 1000 or (
                $gif at 0 or
                (
                    filesize < 4KB and
                    (
                        1 of ( $gen_much_sus* ) or
                        2 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 20KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        3 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 50KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        4 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 100KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        6 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 150KB and
                    (
                        3 of ( $gen_much_sus* ) or
                        7 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 500KB and
                    (
                        4 of ( $gen_much_sus* ) or
                        8 of ( $gen_bit_sus* )
                    )
                )
            )
        )
}

rule WEBSHELL_PHP_Base64_Encoded_Payloads : FILE {
    meta:
        description = "php webshell containing base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "88d0d4696c9cb2d37d16e330e236cb37cfaec4cd"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "e726cd071915534761822805724c6c6bfe0fcac604a86f09437f03f301512dc5"
        hash = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
        hash = "8cc9802769ede56f1139abeaa0735526f781dff3b6c6334795d1d0f19161d076"
        hash = "4cda0c798908b61ae7f4146c6218d7b7de14cbcd7c839edbdeb547b5ae404cd4"
        hash = "afd9c9b0df0b2ca119914ea0008fad94de3bd93c6919f226b793464d4441bdf4"
        hash = "b2048dc30fc7681094a0306a81f4a4cc34f0b35ccce1258c20f4940300397819"
        hash = "da6af9a4a60e3a484764010fbf1a547c2c0a2791e03fc11618b8fc2605dceb04"
        hash = "222cd9b208bd24955bcf4f9976f9c14c1d25e29d361d9dcd603d57f1ea2b0aee"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "6b6cd1ef7e78e37cbcca94bfb5f49f763ba2f63ed8b33bc4d7f9e5314c87f646"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "e2b1dfcfaa61e92526a3a444be6c65330a8db4e692543a421e19711760f6ffe2"

        id = "4e42b47d-725b-5e1f-9408-6c6329f60506"
    strings:
        $decode1 = "base64_decode" fullword nocase wide ascii
        $decode2 = "openssl_decrypt" fullword nocase wide ascii
        // exec
        $one1 = "leGVj"
        $one2 = "V4ZW"
        $one3 = "ZXhlY"
        $one4 = "UAeABlAGMA"
        $one5 = "lAHgAZQBjA"
        $one6 = "ZQB4AGUAYw"
        // shell_exec
        $two1 = "zaGVsbF9leGVj"
        $two2 = "NoZWxsX2V4ZW"
        $two3 = "c2hlbGxfZXhlY"
        $two4 = "MAaABlAGwAbABfAGUAeABlAGMA"
        $two5 = "zAGgAZQBsAGwAXwBlAHgAZQBjA"
        $two6 = "cwBoAGUAbABsAF8AZQB4AGUAYw"
        // passthru
        $three1 = "wYXNzdGhyd"
        $three2 = "Bhc3N0aHJ1"
        $three3 = "cGFzc3Rocn"
        $three4 = "AAYQBzAHMAdABoAHIAdQ"
        $three5 = "wAGEAcwBzAHQAaAByAHUA"
        $three6 = "cABhAHMAcwB0AGgAcgB1A"
        // system
        $four1 = "zeXN0ZW"
        $four2 = "N5c3Rlb"
        $four3 = "c3lzdGVt"
        $four4 = "MAeQBzAHQAZQBtA"
        $four5 = "zAHkAcwB0AGUAbQ"
        $four6 = "cwB5AHMAdABlAG0A"
        // popen
        $five1 = "wb3Blb"
        $five2 = "BvcGVu"
        $five3 = "cG9wZW"
        $five4 = "AAbwBwAGUAbg"
        $five5 = "wAG8AcABlAG4A"
        $five6 = "cABvAHAAZQBuA"
        // proc_open
        $six1 = "wcm9jX29wZW"
        $six2 = "Byb2Nfb3Blb"
        $six3 = "cHJvY19vcGVu"
        $six4 = "AAcgBvAGMAXwBvAHAAZQBuA"
        $six5 = "wAHIAbwBjAF8AbwBwAGUAbg"
        $six6 = "cAByAG8AYwBfAG8AcABlAG4A"
        // pcntl_exec
        $seven1 = "wY250bF9leGVj"
        $seven2 = "BjbnRsX2V4ZW"
        $seven3 = "cGNudGxfZXhlY"
        $seven4 = "AAYwBuAHQAbABfAGUAeABlAGMA"
        $seven5 = "wAGMAbgB0AGwAXwBlAHgAZQBjA"
        $seven6 = "cABjAG4AdABsAF8AZQB4AGUAYw"
        // eval
        $eight1 = "ldmFs"
        $eight2 = "V2YW"
        $eight3 = "ZXZhb"
        $eight4 = "UAdgBhAGwA"
        $eight5 = "lAHYAYQBsA"
        $eight6 = "ZQB2AGEAbA"
        // assert
        $nine1 = "hc3Nlcn"
        $nine2 = "Fzc2Vyd"
        $nine3 = "YXNzZXJ0"
        $nine4 = "EAcwBzAGUAcgB0A"
        $nine5 = "hAHMAcwBlAHIAdA"
        $nine6 = "YQBzAHMAZQByAHQA"

        // false positives

        // execu
        $execu1 = "leGVjd"
        $execu2 = "V4ZWN1"
        $execu3 = "ZXhlY3"

        // esystem like e.g. filesystem
        $esystem1 = "lc3lzdGVt"
        $esystem2 = "VzeXN0ZW"
        $esystem3 = "ZXN5c3Rlb"

        // opening
        $opening1 = "vcGVuaW5n"
        $opening2 = "9wZW5pbm"
        $opening3 = "b3BlbmluZ"

        // false positives
        $fp1 = { D0 CF 11 E0 A1 B1 1A E1 }
        // api.telegram
        $fp2 = "YXBpLnRlbGVncmFtLm9"
        // Log files
        $fp3 = " GET /"
        $fp4 = " POST /"

    $fpa1 = "/cn=Recipients"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 300KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not any of ( $fp* ) and any of ( $decode* ) and
        ( ( any of ( $one* ) and not any of ( $execu* ) ) or any of ( $two* ) or any of ( $three* ) or
        ( any of ( $four* ) and not any of ( $esystem* ) ) or
        ( any of ( $five* ) and not any of ( $opening* ) ) or any of ( $six* ) or any of ( $seven* ) or any of ( $eight* ) or any of ( $nine* ) )
}

rule WEBSHELL_PHP_Unknown_1
{
    meta:
        description = "obfuscated php webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "12ce6c7167b33cc4e8bdec29fb1cfc44ac9487d1"
        hash = "cf4abbd568ce0c0dfce1f2e4af669ad2"
        date = "2021/01/07"
        modified = "2023-04-05"

        id = "93d01a4c-4c18-55d2-b682-68a1f6460889"
    strings:
        $sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
        $sp1 = "=explode(chr(" wide ascii
        $sp2 = "; if (!function_exists('" wide ascii
        $sp3 = " = NULL; for(" wide ascii

    condition:
        filesize <300KB and all of ($sp*)
}

rule WEBSHELL_PHP_Generic_Eval
{
    meta:
        description = "Generic PHP webshell which uses any eval/exec function in the same line with user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
        hash = "90c5cc724ec9cf838e4229e5e08955eec4d7bf95"
        hash = "2b41abc43c5b6c791d4031005bf7c5104a98e98a00ee24620ce3e8e09a78e78f"
        hash = "5c68a0fa132216213b66a114375b07b08dc0cb729ddcf0a29bff9ca7a22eaaf4"
        hash = "de3c01f55d5346577922bbf449faaaaa1c8d1aaa64c01e8a1ee8c9d99a41a1be"
        hash = "124065176d262bde397b1911648cea16a8ff6a4c8ab072168d12bf0662590543"
        hash = "cd7450f3e5103e68741fd086df221982454fbcb067e93b9cbd8572aead8f319b"
        hash = "ab835ce740890473adf5cc804055973b926633e39c59c2bd98da526b63e9c521"
        hash = "31ff9920d401d4fbd5656a4f06c52f1f54258bc42332fc9456265dca7bb4c1ea"
        hash = "64e6c08aa0b542481b86a91cdf1f50c9e88104a8a4572a8c6bd312a9daeba60e"
        hash = "80e98e8a3461d7ba15d869b0641cdd21dd5b957a2006c3caeaf6f70a749ca4bb"
        hash = "93982b8df76080e7ba4520ae4b4db7f3c867f005b3c2f84cb9dff0386e361c35"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "fd5f0f81204ca6ca6e93343500400d5853012e88254874fc9f62efe0fde7ab3c"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "6d042b6393669bb4d98213091cabe554ab192a6c916e86c04d06cc2a4ca92c00"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"


        id = "79cfbd88-f6f7-5cba-a325-0a99962139ca"
    strings:
        // new: eval($GLOBALS['_POST'
        $geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]*(\(base64_decode)?(\(stripslashes)?[\t ]*(\(trim)?[\t ]*\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
        // Log files
        $gfp_3 = " GET /"
        $gfp_4 = " POST /"
    condition:
        filesize < 300KB and not (
            any of ( $gfp* )
        )
        and $geval
}

rule WEBSHELL_PHP_Double_Eval_Tiny
{
    meta:
        description = "PHP webshell which probably hides the input inside an eval()ed obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021-01-11"
        modified = "2023-07-05"
        hash = "f66fb918751acc7b88a17272a044b5242797976c73a6e54ac6b04b02f61e9761"
        hash = "6b2f0a3bd80019dea536ddbf92df36ab897dd295840cb15bb7b159d0ee2106ff"
        hash = "aabfd179aaf716929c8b820eefa3c1f613f8dcac"
        hash = "9780c70bd1c76425d4313ca7a9b89dda77d2c664"
        hash = "006620d2a701de73d995fc950691665c0692af11"


        id = "868db363-83d3-57e2-ac8d-c6125e9bdd64"
    strings:
        $payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase wide ascii
        $fp1 = "clone" fullword wide ascii
        $fp2 = "* @assert" ascii
        $fp3 = "*@assert" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize > 70 and filesize < 300 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and #payload >= 2 and not any of ( $fp* )
}

rule WEBSHELL_PHP_OBFUSC
{
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "eec9ac58a1e763f5ea0f7fa249f1fe752047fa60"
        hash = "181a71c99a4ae13ebd5c94bfc41f9ec534acf61cd33ef5bce5fb2a6f48b65bf4"
        hash = "76d4e67e13c21662c4b30aab701ce9cdecc8698696979e504c288f20de92aee7"
        hash = "1d0643927f04cb1133f00aa6c5fa84aaf88e5cf14d7df8291615b402e8ab6dc2"
        id = "f66e337b-8478-5cd3-b01a-81133edaa8e5"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_obfuscation_multi
        $o1 = "chr(" nocase wide ascii
        $o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o3 = "goto" fullword nocase wide ascii
        $o4 = "\\x9" wide ascii
        $o5 = "\\x3" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        $fp1 = "$goto" wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            // allow different amounts of potential obfuscation functions depending on filesize
            not $fp1 and (
                (
                        filesize < 20KB and
                        (
                            ( #o1+#o2 ) > 50 or
                            #o3 > 10 or
                            ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
                        )
                ) or (
                        filesize < 200KB and
                        (
                            ( #o1+#o2 ) > 200 or
                            #o3 > 30 or
                            ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 30
                        )

                )
            )


        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )

}

rule WEBSHELL_PHP_OBFUSC_Encoded
{
    meta:
        description = "PHP webshell obfuscated by encoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/04/18"
        modified = "2023-04-05"
        score = 70
        hash = "119fc058c9c5285498a47aa271ac9a27f6ada1bf4d854ccd4b01db993d61fc52"
        hash = "d5ca3e4505ea122019ea263d6433221030b3f64460d3ce2c7d0d63ed91162175"
        hash = "8a1e2d72c82f6a846ec066d249bfa0aaf392c65149d39b7b15ba19f9adc3b339"


        id = "134c1189-1b41-58d5-af66-beaa4795a704"
    strings:
        // one without plain e, one without plain v, to avoid hitting on plain "eval("
        $enc_eval1 = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
        $enc_eval2 = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
        // one without plain a, one without plain s, to avoid hitting on plain "assert("
        $enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
        $enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $enc* )
}

rule WEBSHELL_PHP_OBFUSC_Encoded_Mixed_Dec_And_Hex
{
    meta:
        description = "PHP webshell obfuscated by encoding of mixed hex and dec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/18"
        modified = "2023-04-05"
        hash = "0e21931b16f30b1db90a27eafabccc91abd757fa63594ba8a6ad3f477de1ab1c"
        hash = "929975272f0f42bf76469ed89ebf37efcbd91c6f8dac1129c7ab061e2564dd06"
        hash = "88fce6c1b589d600b4295528d3fcac161b581f739095b99cd6c768b7e16e89ff"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "50389c3b95a9de00220fc554258fda1fef01c62dad849e66c8a92fc749523457"
        hash = "c4ab4319a77b751a45391aa01cde2d765b095b0e3f6a92b0b8626d5c7e3ad603"
        hash = "df381f04fca2522e2ecba0f5de3f73a655d1540e1cf865970f5fa3bf52d2b297"
        hash = "401388d8b97649672d101bf55694dd175375214386253d0b4b8d8d801a89549c"
        hash = "99fc39a12856cc1a42bb7f90ffc9fe0a5339838b54a63e8f00aa98961c900618"
        hash = "fb031af7aa459ee88a9ca44013a76f6278ad5846aa20e5add4aeb5fab058d0ee"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
        hash = "0ff05e6695074f98b0dee6200697a997c509a652f746d2c1c92c0b0a0552ca47"

        id = "9ae920e2-17c8-58fd-8566-90d461a54943"
    strings:
        // "e\x4a\x48\x5a\x70\x63\62\154\x30\131\171\101\x39\111\x43\x52\x66\x51\
        //$mix = /['"]\\x?[0-9a-f]{2,3}[\\\w]{2,20}\\\d{1,3}[\\\w]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase
        $mix = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $mix* )
}

rule WEBSHELL_PHP_OBFUSC_Tiny
{
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "b7b7aabd518a2f8578d4b1bc9a3af60d155972f1"
        hash = "694ec6e1c4f34632a9bd7065f73be473"
        hash = "5c871183444dbb5c8766df6b126bd80c624a63a16cc39e20a0f7b002216b2ba5"

        id = "d78e495f-54d2-5f5f-920f-fb6612afbca3"
    strings:
        // 'ev'.'al'
        $obf1 = /\w'\.'\w/ wide ascii
        $obf2 = /\w\"\.\"\w/ wide ascii
        $obf3 = "].$" wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        //any of them or
        filesize < 500 and not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and
        ( ( #obf1 + #obf2 ) > 2 or #obf3 > 10 )
}

rule WEBSHELL_PHP_OBFUSC_Str_Replace
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "691305753e26884d0f930cda0fe5231c6437de94"
        hash = "7efd463aeb5bf0120dc5f963b62463211bd9e678"
        hash = "fb655ddb90892e522ae1aaaf6cd8bde27a7f49ef"
        hash = "d1863aeca1a479462648d975773f795bb33a7af2"
        hash = "4d31d94b88e2bbd255cf501e178944425d40ee97"
        hash = "e1a2af3477d62a58f9e6431f5a4a123fb897ea80"

        id = "1f5b93c9-bdeb-52c7-a99a-69869634a574"
    strings:
        $payload1 = "str_replace" fullword wide ascii
        $payload2 = "function" fullword wide ascii
        $goto = "goto" fullword wide ascii
        //$hex  = "\\x"
        $chr1  = "\\61" wide ascii
        $chr2  = "\\112" wide ascii
        $chr3  = "\\120" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 300KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $payload* ) and #goto > 1 and
        ( #chr1 > 10 or #chr2 > 10 or #chr3 > 10 )
}

rule WEBSHELL_PHP_OBFUSC_Fopo
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "fbcff8ea5ce04fc91c05384e847f2c316e013207"
        hash = "6da57ad8be1c587bb5cc8a1413f07d10fb314b72"
        hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"
        date = "2021/01/12"
        modified = "2023-04-05"

        id = "a298e99d-1ba8-58c8-afb9-fc988ea91e9a"
    strings:
        $payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase wide ascii
        // ;@eval(
        $one1 = "7QGV2YWwo" wide ascii
        $one2 = "tAZXZhbC" wide ascii
        $one3 = "O0BldmFsK" wide ascii
        $one4 = "sAQABlAHYAYQBsACgA" wide ascii
        $one5 = "7AEAAZQB2AGEAbAAoA" wide ascii
        $one6 = "OwBAAGUAdgBhAGwAKA" wide ascii
        // ;@assert(
        $two1 = "7QGFzc2VydC" wide ascii
        $two2 = "tAYXNzZXJ0K" wide ascii
        $two3 = "O0Bhc3NlcnQo" wide ascii
        $two4 = "sAQABhAHMAcwBlAHIAdAAoA" wide ascii
        $two5 = "7AEAAYQBzAHMAZQByAHQAKA" wide ascii
        $two6 = "OwBAAGEAcwBzAGUAcgB0ACgA" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 3000KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $payload and
        ( any of ( $one* ) or any of ( $two* ) )
}

rule WEBSHELL_PHP_Gzinflated
{
    meta:
        description = "PHP webshell which directly eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "49e5bc75a1ec36beeff4fbaeb16b322b08cf192d"
        hash = "6f36d201cd32296bad9d5864c7357e8634f365cc"
        hash = "ab10a1e69f3dfe7c2ad12b2e6c0e66db819c2301"
        hash = "a6cf337fe11fe646d7eee3d3f09c7cb9643d921d"
        hash = "07eb6634f28549ebf26583e8b154c6a579b8a733"

        id = "9cf99ae4-9f7c-502f-9294-b531002953d6"
    strings:
        $payload2 = /eval\s?\(\s?("\?>".)?gzinflate\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload4 = /eval\s?\(\s?("\?>".)?gzuncompress\s?\(\s?(base64_decode|gzuncompress)/ wide ascii nocase
        $payload6 = /eval\s?\(\s?("\?>".)?gzdecode\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload7 = /eval\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload8 = /eval\s?\(\s?pack\s?\(/ wide ascii nocase

        // api.telegram
        $fp1 = "YXBpLnRlbGVncmFtLm9"

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and 1 of ( $payload* ) and not any of ( $fp* )
}

rule WEBSHELL_PHP_OBFUSC_3
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/17"
        modified = "2023-07-05"
        hash = "11bb1fa3478ec16c00da2a1531906c05e9c982ea"
        hash = "d6b851cae249ea6744078393f622ace15f9880bc"
        hash = "14e02b61905cf373ba9234a13958310652a91ece"
        hash = "6f97f607a3db798128288e32de851c6f56e91c1d"

        id = "f2017e6f-0623-53ff-aa26-a479f3a02024"
    strings:
        $obf1 = "chr(" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback3 = /\barray_diff_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback4 = /\barray_filter[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback7 = /\barray_map[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback8 = /\barray_reduce[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback11 = /\barray_udiff[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback14 = /\barray_uintersect[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback15 = /\barray_walk_recursive[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback16 = /\barray_walk[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback17 = /\bassert_options[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback18 = /\buasort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback19 = /\buksort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback20 = /\busort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback22 = /\bspl_autoload_register[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback23 = /\biterator_apply[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback24 = /\bcall_user_func[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback25 = /\bcall_user_func_array[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback27 = /\bregister_tick_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback28 = /\bset_error_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback29 = /\bset_exception_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback32 = /\bsqlite_create_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii

        $m_callback1 = /\bfilter_var[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
        $cfp3 = "<?phpclass WPML" ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_php_obfuscation_single
        $cobfs1 = "gzinflate" fullword nocase wide ascii
        $cobfs2 = "gzuncompress" fullword nocase wide ascii
        $cobfs3 = "gzdecode" fullword nocase wide ascii
        $cobfs4 = "base64_decode" fullword nocase wide ascii
        $cobfs5 = "pack" fullword nocase wide ascii
        $cobfs6 = "undecode" fullword nocase wide ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
        $gen_much_sus93 = "eval(\"/*" wide ascii
        $gen_much_sus94 = "=$_COOKIE;" wide ascii

        $gif = { 47 49 46 38 }


    condition:
        //any of them or
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and
        ( (
            not any of ( $cfp* ) and
        (
            any of ( $callback* )  or
            all of ( $m_callback* )
        )
        )
        or (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        ) and (
            any of ( $cobfs* )
        )
        and
        ( filesize < 1KB or
        ( filesize < 3KB and
        ( (
        $gif at 0 or
        (
            filesize < 4KB and
            (
                1 of ( $gen_much_sus* ) or
                2 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 20KB and
            (
                2 of ( $gen_much_sus* ) or
                3 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 50KB and
            (
                2 of ( $gen_much_sus* ) or
                4 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 100KB and
            (
                2 of ( $gen_much_sus* ) or
                6 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 150KB and
            (
                3 of ( $gen_much_sus* ) or
                7 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 500KB and
            (
                4 of ( $gen_much_sus* ) or
                8 of ( $gen_bit_sus* )
            )
        )
        )
        or #obf1 > 10 ) ) )
}

rule WEBSHELL_PHP_Includer_Eval
{
    meta:
        description = "PHP webshell which eval()s another included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/13"
        modified = "2023-04-05"
        hash = "3a07e9188028efa32872ba5b6e5363920a6b2489"
        hash = "ab771bb715710892b9513b1d075b4e2c0931afb6"
        hash = "202dbcdc2896873631e1a0448098c820c82bcc8385a9f7579a0dc9702d76f580"
        hash = "b51a6d208ec3a44a67cce16dcc1e93cdb06fe150acf16222815333ddf52d4db8"

        id = "995fcc34-f91e-5c9c-97b1-84eed1714d40"
    strings:
        $payload1 = "eval" fullword wide ascii
        $payload2 = "assert" fullword wide ascii
        $include1 = "$_FILE" wide ascii
        $include2 = "include" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 200 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and 1 of ( $payload* ) and 1 of ( $include* )
}

rule WEBSHELL_PHP_Includer_Tiny
{
    meta:
        description = "Suspicious: Might be PHP webshell includer, check the included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/17"
        modified = "2023-07-05"
        hash = "0687585025f99596508783b891e26d6989eec2ba"
        hash = "9e856f5cb7cb901b5003e57c528a6298341d04dc"
        hash = "b3b0274cda28292813096a5a7a3f5f77378b8905205bda7bb7e1a679a7845004"

        id = "9bf96ddc-d984-57eb-9803-0b01890711b5"
    strings:
        $php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 100 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $php_include* )
}

rule WEBSHELL_PHP_Dynamic
{
    meta:
        description = "PHP webshell using function name from variable, e.g. $a='ev'.'al'; $a($code)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/13"
        modified = "2023-10-06"
        score = 60
        hash = "65dca1e652d09514e9c9b2e0004629d03ab3c3ef"
        hash = "b8ab38dc75cec26ce3d3a91cb2951d7cdd004838"
        hash = "c4765e81550b476976604d01c20e3dbd415366df"
        hash = "2e11ba2d06ebe0aa818e38e24a8a83eebbaae8877c10b704af01bf2977701e73"

        id = "58ad94bc-93c8-509c-9d3a-c9a26538d60c"
    strings:
        $pd_fp1 = "whoops_add_stack_frame" wide ascii
        $pd_fp2 = "new $ec($code, $mode, $options, $userinfo);" wide ascii
        $pd_fp3 = "($i)] = 600;" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
        // ${'_'.$_}["_"](${'_'.$_}["__"]
        $dynamic8 = /\${[^}]{1,20}}(\[[^\]]{1,20}\])?\(\${/ wide ascii

        $fp1 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 24 63 29 3B } /* <?php\x0a\x0a$a($b = 3, $c); */
        $fp2 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 2E 2E 2E 20 24 63 29 3B } /* <?php\x0a\x0a$a($b = 3, ... $c); */
        $fp3 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 74 61 74 69 63 3A 3A 24 62 28 29 3B} /* <?php\x0a\x0a$a = new static::$b(); */
        $fp4 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 65 6C 66 3A 3A 24 62 28 29 3B } /* <?php\x0a\x0a$a = new self::$b(); */
        $fp5 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 5C 22 7B 24 76 61 72 43 61 6C 6C 61 62 6C 65 28 29 7D 5C 22 3B } /* <?php\x0a\x0a$a = \"{$varCallable()}\"; */
        $fp6 = "// TODO error about missing expression" /* <?php\x0a// TODO error about missing expression\x0a$a($b = 3, $c,); */
        $fp7 = "// This is an invalid location for an attribute, "
        $fp8 = "/* Auto-generated from php/php-langspec tests */"
    condition:
        filesize > 20 and filesize < 200 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $dynamic* )
        )
        and not any of ( $pd_fp* )
        and not 1 of ($fp*)
}

rule WEBSHELL_PHP_Dynamic_Big
{
    meta:
        description = "PHP webshell using $a($code) for kind of eval with encoded blob to decode, e.g. b374k"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/02/07"
        modified = "2023-09-18"
        score = 50
        hash = "6559bfc4be43a55c6bb2bd867b4c9b929713d3f7f6de8111a3c330f87a9b302c"
        hash = "9e82c9c2fa64e26fd55aa18f74759454d89f968068d46b255bd4f41eb556112e"
        hash = "6def5296f95e191a9c7f64f7d8ac5c529d4a4347ae484775965442162345dc93"
        hash = "dadfdc4041caa37166db80838e572d091bb153815a306c8be0d66c9851b98c10"
        hash = "0a4a292f6e08479c04e5c4fdc3857eee72efa5cd39db52e4a6e405bf039928bd"
        hash = "4326d10059e97809fb1903eb96fd9152cc72c376913771f59fa674a3f110679e"
        hash = "b49d0f942a38a33d2b655b1c32ac44f19ed844c2479bad6e540f69b807dd3022"
        hash = "575edeb905b434a3b35732654eedd3afae81e7d99ca35848c509177aa9bf9eef"
        hash = "ee34d62e136a04e2eaf84b8daa12c9f2233a366af83081a38c3c973ab5e2c40f"

        id = "a5caab93-7b94-59d7-bbca-f9863e81b9e5"
    strings:
        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_php_new_long
        // no <?=
        $new_php2 = "<?php" nocase wide ascii
        $new_php3 = "<script language=\"php" nocase wide ascii
        $php_short = "<?"

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
        $dynamic8 = "eval(" wide ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        $gen_bit_sus27 = "zuncomp" wide ascii
        $gen_bit_sus28 = "ase6" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        $gen_bit_sus65 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
        $gen_bit_sus99 = "$password = " wide ascii
        $gen_bit_sus100 = "();$" wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "DEFACE" fullword wide ascii
        $gen_much_sus93 = "Bypass" fullword wide ascii
        $gen_much_sus94 = /eval\s{2,20}\(/ nocase wide ascii
        $gen_much_sus100 = "rot13" wide ascii
        $gen_much_sus101 = "ini_set('error_log'" wide ascii
        $gen_much_sus102 = "base64_decode(base64_decode(" wide ascii
        $gen_much_sus103 = "=$_COOKIE;" wide ascii
        // {1}.$ .. |{9}.$
        $gen_much_sus104 = { C0 A6 7B 3? 7D 2E 24 }
        $gen_much_sus105 = "$GLOBALS[\"__" wide ascii
        // those calculations don't make really sense :)
        $gen_much_sus106 = ")-0)" wide ascii
        $gen_much_sus107 = "-0)+" wide ascii
        $gen_much_sus108 = "+0)+" wide ascii
        $gen_much_sus109 = "+(0/" wide ascii
        $gen_much_sus110 = "+(0+" wide ascii
        $gen_much_sus111 = "extract($_REQUEST)" wide ascii
        $gen_much_sus112 = "<?php\t\t\t\t\t\t\t\t\t\t\t" wide ascii
        $gen_much_sus113 = "\t\t\t\t\t\t\t\t\t\t\textract" wide ascii
        $gen_much_sus114 = "\" .\"" wide ascii
        $gen_much_sus115 = "end($_POST" wide ascii

        $weevely1 = /';\n\$\w\s?=\s?'/ wide ascii
        $weevely2 = /';\x0d\n\$\w\s?=\s?'/ wide ascii // same with \r\n
        $weevely3 = /';\$\w{1,2}='/ wide ascii
        $weevely4 = "str_replace" fullword wide ascii

        $gif = { 47 49 46 38 }

        $fp1 = "# Some examples from obfuscated malware:" ascii
        $fp2 = "* @package   PHP_CodeSniffer" ascii
        $fp3 = ".jQuery===" ascii
        $fp4 = "* @param string $lstat encoded LStat string" ascii
    condition:
        //any of them or
        not (
            uint16(0) == 0x5a4d or
            // <?xml
            uint32be(0) == 0x3c3f786d  or
            // <?XML
            uint32be(0) == 0x3c3f584d  or
            $dex at 0 or
            $pack at 0 or
            // fp on jar with zero compression
            uint16(0) == 0x4b50 or
            1 of ($fp*)
        )
        and (
            any of ( $new_php* ) or
            $php_short at 0
        )
        and (
            any of ( $dynamic* )
        )
        and
            (
            $gif at 0 or
        (
            (
                filesize < 1KB and
                (
                    1 of ( $gen_much_sus* )
                )
            ) or (
                filesize < 2KB and
                (
                    ( #weevely1 + #weevely2 + #weevely3 ) > 2 and
                    #weevely4 > 1
                )
            ) or (
                filesize < 4KB and
                (
                    1 of ( $gen_much_sus* ) or
                    2 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 20KB and
                (
                    2 of ( $gen_much_sus* ) or
                    4 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 50KB and
                (
                    3 of ( $gen_much_sus* ) or
                    5 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 100KB and
                (
                    3 of ( $gen_much_sus* ) or
                    6 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 160KB and
                (
                    3 of ( $gen_much_sus* ) or
                    7 of ( $gen_bit_sus* ) or
                    (
                        // php files which use strings in the full ascii8 spectrum have a much hioher deviation than normal php-code
                        // e.g. 4057005718bb18b51b02d8b807265f8df821157ac47f78ace77f21b21fc77232
                        math.deviation(500, filesize-500, 89.0) > 70
                        // uncomment and include an "and" above for debugging, also import on top of file. needs yara 4.2.0
                        //console.log("high deviation") and
                        //console.log(math.deviation(500, filesize-500, 89.0))
                    )
                    // TODO: requires yara 4.2.0 so wait a bit until that's more common
                    //or
                    //(
                        // big file and just one line = minified
                        //filesize > 10KB and
                        //math.count(0x0A) < 2
                    //)
                )
            ) or (
                filesize < 500KB and
                (
                    4 of ( $gen_much_sus* ) or
                    8 of ( $gen_bit_sus* ) or
                    #gen_much_sus104 > 4

                )
            )
        ) or (
            // file shouldn't be too small to have big enough data for math.entropy
            filesize > 2KB and filesize < 1MB and
            (
                (
                    // base64 :
                    // ignore first and last 500bytes because they usually contain code for decoding and executing
                    math.entropy(500, filesize-500) >= 5.7 and
                    // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                    math.mean(500, filesize-500) > 80 and
                    // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                    // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                    // 89 is the mean of the base64 chars
                    math.deviation(500, filesize-500, 89.0) < 23
                ) or (
                    // gzinflated binary sometimes used in php webshells
                    // ignore first and last 500bytes because they usually contain code for decoding and executing
                    math.entropy(500, filesize-500) >= 7.7 and
                    // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                    math.mean(500, filesize-500) > 120 and
                    math.mean(500, filesize-500) < 136 and
                    // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                    // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                    // 89 is the mean of the base64 chars
                    math.deviation(500, filesize-500, 89.0) > 65
                )
            )
        )
        )
}

rule WEBSHELL_PHP_Encoded_Big
{
    meta:
        description = "PHP webshell using some kind of eval with encoded blob to decode"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/02/07"
        modified = "2023-07-05"
        score = 50
        hash = "1d4b374d284c12db881ba42ee63ebce2759e0b14"
        hash = "fc0086caee0a2cd20609a05a6253e23b5e3245b8"
        hash = "b15b073801067429a93e116af1147a21b928b215"
        hash = "74c92f29cf15de34b8866db4b40748243fb938b4"
        hash = "042245ee0c54996608ff8f442c8bafb8"

        id = "c3bb7b8b-c554-5802-8955-c83722498f8b"
    strings:

        //strings from private rule capa_php_new
        $new_php1 = /<\?=[\w\s@$]/ wide ascii
        $new_php2 = "<?php" nocase wide ascii
        $new_php3 = "<script language=\"php" nocase wide ascii
        $php_short = "<?"

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        //console.log(math.entropy(500, filesize-500)) and
        //console.log(math.mean(500, filesize-500)) and
        //console.log(math.deviation(500, filesize-500, 89.0)) and
        //any of them or
        filesize < 1000KB and (
            any of ( $new_php* ) or
        $php_short at 0
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and (
            // file shouldn't be too small to have big enough data for math.entropy
            filesize > 2KB and
        (
            // base64 :
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            math.entropy(500, filesize-500) >= 5.7 and
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            math.mean(500, filesize-500) > 80 and
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            math.deviation(500, filesize-500, 89.0) < 24
        ) or (
            // gzinflated binary sometimes used in php webshells
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            math.entropy(500, filesize-500) >= 7.7 and
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            math.mean(500, filesize-500) > 120 and
            math.mean(500, filesize-500) < 136 and
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            math.deviation(500, filesize-500, 89.0) > 65
        )
        )

}

rule WEBSHELL_PHP_Generic_Backticks
{
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "339f32c883f6175233f0d1a30510caa52fdcaa37"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
        hash = "af987b0eade03672c30c095cee0c7c00b663e4b3c6782615fb7e430e4a7d1d75"
        hash = "67339f9e70a17af16cf51686918cbe1c0604e129950129f67fe445eaff4b4b82"
        hash = "144e242a9b219c5570973ca26d03e82e9fbe7ba2773305d1713288ae3540b4ad"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

        id = "b2f1d8d0-8668-5641-8ce9-c8dd71f51f58"
    strings:
        $backtick = /`\s*{?\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $backtick and filesize < 200
}

rule WEBSHELL_PHP_Generic_Backticks_OBFUSC
{
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "23dc299f941d98c72bd48659cdb4673f5ba93697"
        hash = "e3f393a1530a2824125ecdd6ac79d80cfb18fffb89f470d687323fb5dff0eec1"
        hash = "1e75914336b1013cc30b24d76569542447833416516af0d237c599f95b593f9b"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

        id = "5ecb329f-0755-536d-8bfa-e36158474a0b"
    strings:
        $s1 = /echo[\t ]*\(?`\$/ wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 500 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $s1
}

rule WEBSHELL_PHP_By_String_Known_Webshell
{
    meta:
        description = "Known PHP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021-01-09"
        modified = "2023-04-05"
        score = 70
        hash = "d889da22893536d5965541c30896f4ed4fdf461d"
        hash = "10f4988a191774a2c6b85604344535ee610b844c1708602a355cf7e9c12c3605"
        hash = "7b6471774d14510cf6fa312a496eed72b614f6fc"
        hash = "decda94d40c3fd13dab21e197c8d05f48020fa498f4d0af1f60e29616009e9bf"
        hash = "ef178d332a4780e8b6db0e772aded71ac1a6ed09b923cc359ba3c4efdd818acc"
        hash = "a7a937c766029456050b22fa4218b1f2b45eef0db59b414f79d10791feca2c0b"
        hash = "e7edd380a1a2828929fbde8e7833d6e3385f7652ea6b352d26b86a1e39130ee8"
        hash = "0038946739956c80d75fa9eeb1b5c123b064bbb9381d164d812d72c7c5d13cac"
        hash = "3a7309bad8a5364958081042b5602d82554b97eca04ee8fdd8b671b5d1ddb65d"
        hash = "a78324b9dc0b0676431af40e11bd4e26721a960c55e272d718932bdbb755a098"
        hash = "a27f8cd10cedd20bff51e9a8e19e69361cc8a6a1a700cc64140e66d160be1781"
        hash = "9bbd3462993988f9865262653b35b4151386ed2373592a1e2f8cf0f0271cdb00"
        hash = "459ed1d6f87530910361b1e6065c05ef0b337d128f446253b4e29ae8cc1a3915"
        hash = "12b34d2562518d339ed405fb2f182f95dce36d08fefb5fb67cc9386565f592d1"
        hash = "96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636"
        hash = "312ee17ec9bed4278579443b805c0eb75283f54483d12f9add7d7d9e5f9f6105"
        hash = "15c4e5225ff7811e43506f0e123daee869a8292fc8a38030d165cc3f6a488c95"
        hash = "0c845a031e06925c22667e101a858131bbeb681d78b5dbf446fdd5bca344d765"
        hash = "d52128bcfff5e9a121eab3d76382420c3eebbdb33cd0879fbef7c3426e819695"
        hash = "fe6bc88380e298a6a9e980b57fa659ba93a421489623a20ec90bad0307393411"
        hash = "2b9827df3a9ca5b9ead62d06fefc07885c5d4b0e2b45bb7c0dbacd2ff7f05f55"

        //TODO regex for 96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636 would it be fast enough?

        id = "05ac0e0a-3a19-5c60-b89a-4a300d8c22e7"
    strings:
        $pbs1 = "b374k shell" wide ascii
        $pbs2 = "b374k/b374k" wide ascii
        $pbs3 = "\"b374k" wide ascii
        $pbs4 = "$b374k(\"" wide ascii
        $pbs5 = "b374k " wide ascii
        $pbs6 = "0de664ecd2be02cdd54234a0d1229b43" wide ascii
        $pbs7 = "pwnshell" wide ascii
        $pbs8 = "reGeorg" fullword wide ascii
        $pbs9 = "Georg says, 'All seems fine" fullword wide ascii
        $pbs10 = "My PHP Shell - A very simple web shell" wide ascii
        $pbs11 = "<title>My PHP Shell <?echo VERSION" wide ascii
        $pbs12 = "F4ckTeam" fullword wide ascii
        $pbs15 = "MulCiShell" fullword wide ascii
        // crawler avoid string
        $pbs30 = "bot|spider|crawler|slurp|teoma|archive|track|snoopy|java|lwp|wget|curl|client|python|libwww" wide ascii
        // <?=($pbs_=@$_GET[2]).@$_($_GET[1])?>
        $pbs35 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
        $pbs36 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_POST\s?\[\d\]\)/ wide ascii
        $pbs37 = /@\$_POST\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
        $pbs38 = /@\$_POST\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/ wide ascii
        $pbs39 = /@\$_REQUEST\[\d\]\)\.@\$_\(\$_REQUEST\[\d\]\)/ wide ascii
        $pbs42 = "array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\")" wide ascii
        $pbs43 = "$_SERVER[\"\\x48\\x54\\x54\\x50" wide ascii
        $pbs52 = "preg_replace(\"/[checksql]/e\""
        $pbs53 = "='http://www.zjjv.com'"
        $pbs54 = "=\"http://www.zjjv.com\""

        $pbs60 = /setting\["AccountType"\]\s?=\s?3/
        $pbs61 = "~+d()\"^\"!{+{}"
        $pbs62 = "use function \\eval as "
        $pbs63 = "use function \\assert as "
        $pbs64 = "eval(`/*" wide ascii
        $pbs65 = "/* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" wide ascii
        $pbs66 = "Tas9er" fullword wide ascii
        $pbs67 = "\"TSOP_\";" fullword wide ascii // reverse _POST
        $pbs68 = "str_rot13('nffreg')" wide ascii // rot13(assert)
        $pbs69 = "<?=`{$'" wide ascii
        $pbs70 = "{'_'.$_}[\"_\"](${'_'.$_}[\"_" wide ascii
        $pbs71 = "\"e45e329feb5d925b\"" wide ascii
        $pbs72 = "| PHP FILE MANAGER" wide ascii
        $pbs73 = "\neval(htmlspecialchars_decode(gzinflate(base64_decode($" wide ascii
        $pbs74 = "/*\n\nShellindir.org\n\n*/" wide ascii
        $pbs75 = "$shell = 'uname -a; w; id; /bin/sh -i';" wide ascii
        $pbs76 = "'password' . '/' . 'id' . '/' . " wide ascii
        $pbs77 = "= create_function /*" wide ascii
        $pbs78 = "W3LL M!N! SH3LL" wide ascii
        $pbs79 = "extract($_REQUEST)&&@$" wide ascii
        $pbs80 = "\"P-h-p-S-p-y\"" wide ascii
        $pbs81 = "\\x5f\\x72\\x6f\\x74\\x31\\x33" wide ascii
        $pbs82 = "\\x62\\x61\\x73\\x65\\x36\\x34\\x5f" wide ascii
        $pbs83 = "*/base64_decode/*" wide ascii
        $pbs84 = "\n@eval/*" wide ascii
        $pbs85 = "*/eval/*" wide ascii
        $pbs86 = "*/ array /*" wide ascii
        $pbs87 = "2jtffszJe" wide ascii
        $pbs88 = "edocne_46esab" wide ascii
        $pbs89 = "eval($_HEADERS" wide ascii
        $pbs90 = ">Infinity-Sh3ll<" ascii
        $pbs91 = "Bu adda papka artiq movcuddur!" wide ascii
        $pbs92 = "Get S.H.E.L.L.en" wide ascii
        $pbs93 = "r00t-shell.com" nocase wide ascii
        $pbs94 = "$_SERVER[\"\\x48TTPS" wide ascii
        $pbs95 = "$_SERVER[\"\\x48TTP\\x53" wide ascii
        $pbs96 = "https://www.adminer.org" wide ascii
        $pbs97 = "%2A6%6C%72%6B%64%679%5F%65%68%63%73%77%6F4%2B%6637%6A" wide ascii
        $pbs98 = "%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79" wide ascii

        $front1 = "<?php eval(" nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        filesize < 1000KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and
        ( any of ( $pbs* ) or $front1 in ( 0 .. 60 ) )
}

rule WEBSHELL_PHP_Strings_SUSP
{
    meta:
        description = "typical webshell strings, suspicious"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/12"
        modified = "2023-07-05"
        score = 50
        hash = "0dd568dbe946b5aa4e1d33eab1decbd71903ea04"
        hash = "dde2bdcde95730510b22ae8d52e4344997cb1e74"
        hash = "499db4d70955f7d40cf5cbaf2ecaf7a2"
        hash = "281b66f62db5caab2a6eb08929575ad95628a690"
        hash = "1ab3ae4d613b120f9681f6aa8933d66fa38e4886"

        id = "25f25df5-4398-562b-9383-e01ccb17e8de"
    strings:
        $sstring1 = "eval(\"?>\"" nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not (
            any of ( $gfp* )
        )
        and
        ( 1 of ( $sstring* ) and (
            any of ( $inp* )
        )
        )
}

rule WEBSHELL_PHP_In_Htaccess
{
    meta:
        description = "Use Apache .htaccess to execute php code inside .htaccess"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
        hash = "d79e9b13a32a9e9f3fa36aa1a4baf444bfd2599a"
        hash = "e1d1091fee6026829e037b2c70c228344955c263"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
        hash = "8c9e65cd3ef093cd9c5b418dc5116845aa6602bc92b9b5991b27344d8b3f7ef2"

        id = "0f5edff9-22b2-50c9-ae81-72698ea8e7db"
    strings:
        $hta = "AddType application/x-httpd-php .htaccess" wide ascii

    condition:
        filesize <100KB and $hta
}

rule WEBSHELL_PHP_Function_Via_Get
{
    meta:
        description = "Webshell which sends eval/assert via GET"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/09"
        modified = "2023-04-05"
        hash = "ce739d65c31b3c7ea94357a38f7bd0dc264da052d4fd93a1eabb257f6e3a97a6"
        hash = "d870e971511ea3e082662f8e6ec22e8a8443ca79"
        hash = "73fa97372b3bb829835270a5e20259163ecc3fdbf73ef2a99cb80709ea4572be"

        id = "5fef1063-2f9f-516e-86f6-cfd98bb05e6e"
    strings:
        $sr0 = /\$_GET\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
        $sr1 = /\$_POST\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
        $sr2 = /\$_POST\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
        $sr3 = /\$_GET\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
        $sr4 = /\$_REQUEST\s?\[.{1,30}\]\(\$_REQUEST\s?\[/ wide ascii
        $sr5 = /\$_SERVER\s?\[HTTP_.{1,30}\]\(\$_SERVER\s?\[HTTP_/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

    condition:
        filesize < 500KB and not (
            any of ( $gfp* )
        )
        and any of ( $sr* )
}

rule WEBSHELL_PHP_Writer
{
    meta:
        description = "PHP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/04/17"
        modified = "2023-07-05"
        score = 50
        hash = "ec83d69512aa0cc85584973f5f0850932fb1949fb5fb2b7e6e5bbfb121193637"
        hash = "407c15f94a33232c64ddf45f194917fabcd2e83cf93f38ee82f9720e2635fa64"
        hash = "988b125b6727b94ce9a27ea42edc0ce282c5dfeb"
        hash = "0ce760131787803bbef216d0ee9b5eb062633537"
        hash = "20281d16838f707c86b1ff1428a293ed6aec0e97"

        id = "05bb3e0c-69b2-5176-a3eb-e6ba2d72a205"
    strings:
        $sus3 = "'upload'" wide ascii
        $sus4 = "\"upload\"" wide ascii
        $sus5 = "\"Upload\"" wide ascii
        $sus6 = "gif89" wide ascii
        //$sus13= "<textarea " wide ascii
        $sus16= "Army" fullword wide ascii
        $sus17= "error_reporting( 0 )" wide ascii
        $sus18= "' . '" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" wide ascii
        $php_multi_write2 = "fwrite(" wide ascii
        $php_write1 = "move_uploaded_file" fullword wide ascii
        $php_write2 = "copy" fullword wide ascii

    condition:
        //any of them or
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
        any of ( $php_write* ) or
        all of ( $php_multi_write* )
        )
        and
        (
            filesize < 400 or
            (
                filesize < 4000 and 1 of ( $sus* )
            )
        )
}

rule WEBSHELL_ASP_Writer
{
    meta:
        description = "ASP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/07"
        modified = "2023-07-05"
        score = 60
        hash = "df6eaba8d643c49c6f38016531c88332e80af33c"
        hash = "83642a926291a499916e8c915dacadd0d5a8b91f"
        hash = "5417fad68a6f7320d227f558bf64657fe3aa9153"
        hash = "97d9f6c411f54b56056a145654cd00abca2ff871"
        hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"

        id = "a1310e22-f485-5f06-8f1a-4cf9ae8413a1"
    strings:
        $sus1 = "password" fullword wide ascii
        $sus2 = "pwd" fullword wide ascii
        $sus3 = "<asp:TextBox" fullword nocase wide ascii
        $sus4 = "\"upload\"" wide ascii
        $sus5 = "\"Upload\"" wide ascii
        $sus6 = "gif89" wide ascii
        $sus7 = "\"&\"" wide ascii
        $sus8 = "authkey" fullword wide ascii
        $sus9 = "AUTHKEY" fullword wide ascii
        $sus10= "test.asp" fullword wide ascii
        $sus11= "cmd.asp" fullword wide ascii
        $sus12= ".Write(Request." wide ascii
        $sus13= "<textarea " wide ascii
        $sus14= "\"unsafe" fullword wide ascii
        $sus15= "'unsafe" fullword wide ascii
        $sus16= "Army" fullword wide ascii
        $sus17= "response.BinaryWrite" wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_write_way_one4 = "BinaryStream.WriteText" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        and
        ( filesize < 400 or
        ( filesize < 6000 and 1 of ( $sus* ) ) )
}

rule WEBSHELL_ASP_OBFUSC
{
    meta:
        description = "ASP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "ad597eee256de51ffb36518cd5f0f4aa0f254f27517d28fb7543ae313b15e112"
        hash = "e0d21fdc16e0010b88d0197ebf619faa4aeca65243f545c18e10859469c1805a"
        hash = "54a5620d4ea42e41beac08d8b1240b642dd6fd7c"
        hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"
        hash = "be2fedc38fc0c3d1f925310d5156ccf3d80f1432"
        hash = "3175ee00fc66921ebec2e7ece8aa3296d4275cb5"
        hash = "d6b96d844ac395358ee38d4524105d331af42ede"
        hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"

        id = "3960b692-9f6f-52c5-b881-6f9e1b3ac555"
    strings:
        $asp_obf1 = "/*-/*-*/" wide ascii
        $asp_obf2 = "u\"+\"n\"+\"s" wide ascii
        $asp_obf3 = "\"e\"+\"v" wide ascii
        $asp_obf4 = "a\"+\"l\"" wide ascii
        $asp_obf5 = "\"+\"(\"+\"" wide ascii
        $asp_obf6 = "q\"+\"u\"" wide ascii
        $asp_obf7 = "\"u\"+\"e" wide ascii
        $asp_obf8 = "/*//*/" wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

        //strings from private rule capa_asp_obfuscation_multi
        // many Chr or few and a loop????
        //$loop1 = "For "
        //$o1 = "chr(" nocase wide ascii
        //$o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o4 = "\\x8" wide ascii
        $o5 = "\\x9" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        //$o10 = " & \"" wide ascii
        //$o11 = " += \"" wide ascii
        // used for e.g. "scr"&"ipt"

        $m_multi_one1 = "Replace(" wide ascii
        $m_multi_one2 = "Len(" wide ascii
        $m_multi_one3 = "Mid(" wide ascii
        $m_multi_one4 = "mid(" wide ascii
        $m_multi_one5 = ".ToString(" wide ascii

        /*
        $m_multi_one5 = "InStr(" wide ascii
        $m_multi_one6 = "Function" wide ascii

        $m_multi_two1 = "for each" wide ascii
        $m_multi_two2 = "split(" wide ascii
        $m_multi_two3 = " & chr(" wide ascii
        $m_multi_two4 = " & Chr(" wide ascii
        $m_multi_two5 = " & Chr (" wide ascii

        $m_multi_three1 = "foreach" fullword wide ascii
        $m_multi_three2 = "(char" wide ascii

        $m_multi_four1 = "FromBase64String(" wide ascii
        $m_multi_four2 = ".Replace(" wide ascii
        $m_multi_five1 = "String.Join(\"\"," wide ascii
        $m_multi_five2 = ".Trim(" wide ascii
        $m_any1 = " & \"2" wide ascii
        $m_any2 = " += \"2" wide ascii
        */

        $m_fp1 = "Author: Andre Teixeira - andret@microsoft.com" /* FPs with 0227f4c366c07c45628b02bae6b4ad01 */
        $m_fp2 = "DataBinder.Eval(Container.DataItem" ascii wide


        //strings from private rule capa_asp_obfuscation_obviously
        $oo1 = /\w\"&\"\w/ wide ascii
        $oo2 = "*/\").Replace(\"/*" wide ascii

    condition:
        filesize < 100KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) and
        ( (
        (
            filesize < 100KB and
            (
                //( #o1+#o2 ) > 50 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
            )
        ) or (
            filesize < 5KB and
            (
                //( #o1+#o2 ) > 10 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 5 or
                (
                    //( #o1+#o2 ) > 1 and
                    ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 3
                )

            )
        ) or (
            filesize < 700 and
            (
                //( #o1+#o2 ) > 1 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 3 or
                ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 2
            )
        )
        )
        or any of ( $asp_obf* ) ) or (
        (
            filesize < 100KB and
            (
                ( #oo1 ) > 2 or
                $oo2
            )
        ) or (
            filesize < 25KB and
            (
                ( #oo1 ) > 1
            )
        ) or (
            filesize < 1KB and
            (
                ( #oo1 ) > 0
            )
        )
        )
        )
        and not any of ( $m_fp* )
}

// rule WEBSHELL_ASP_Generic_Eval_On_Input
// {
//     meta:
//         description = "Generic ASP webshell which uses any eval/exec function directly on user input"
//         license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
//         author = "Arnim Rupp (https://github.com/ruppde)"
//         reference = "Internal Research"
//         score = 75
//         date = "2021/01/07"
//         modified = "2023-04-05"
//         hash = "d6b96d844ac395358ee38d4524105d331af42ede"
//         hash = "9be2088d5c3bfad9e8dfa2d7d7ba7834030c7407"
//         hash = "a1df4cfb978567c4d1c353e988915c25c19a0e4a"
//         hash = "069ea990d32fc980939fffdf1aed77384bf7806bc57c0a7faaff33bd1a3447f6"
// 
//         id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
//     strings:
//         $payload_and_input0 = /\beval_r\s{0,20}\(Request\(/ nocase wide ascii
//         $payload_and_input1 = /\beval[\s\(]{1,20}request[.\(\[]/ nocase wide ascii
//         $payload_and_input2 = /\bexecute[\s\(]{1,20}request\(/ nocase wide ascii
//         $payload_and_input4 = /\bExecuteGlobal\s{1,20}request\(/ nocase wide ascii
// 
//         //strings from private rule capa_asp
//         $tagasp_short1 = /<%[^"]/ wide ascii
//         // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
//         $tagasp_short2 = "%>" wide ascii
// 
//         // classids for scripting host etc
//         $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
//         $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
//         $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
//         $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
//         $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
//         $tagasp_long10 = "<%@ " wide ascii
//         // <% eval
//         $tagasp_long11 = /<% \w/ nocase wide ascii
//         $tagasp_long12 = "<%ex" nocase wide ascii
//         $tagasp_long13 = "<%ev" nocase wide ascii
// 
//         // <%@ LANGUAGE = VBScript.encode%>
//         // <%@ Language = "JScript" %>
// 
//         // <%@ WebHandler Language="C#" class="Handler" %>
//         // <%@ WebService Language="C#" Class="Service" %>
// 
//         // <%@Page Language="Jscript"%>
//         // <%@ Page Language = Jscript %>
//         // <%@PAGE LANGUAGE=JSCRIPT%>
//         // <%@ Page Language="Jscript" validateRequest="false" %>
//         // <%@ Page Language = Jscript %>
//         // <%@ Page Language="C#" %>
//         // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
//         // <script runat="server" language="JScript">
//         // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
//         // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
//         // <msxsl:script language="JScript" ...
//         $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
// 
//         $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
//         $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
// 
//         // avoid hitting php
//         $php1 = "<?php"
//         $php2 = "<?="
// 
//         // avoid hitting jsp
//         $jsp1 = "=\"java." wide ascii
//         $jsp2 = "=\"javax." wide ascii
//         $jsp3 = "java.lang." wide ascii
//         $jsp4 = "public" fullword wide ascii
//         $jsp5 = "throws" fullword wide ascii
//         $jsp6 = "getValue" fullword wide ascii
//         $jsp7 = "getBytes" fullword wide ascii
// 
//         $perl1 = "PerlScript" fullword
// 
// 
//     condition:
//         ( filesize < 1100KB and (
//         (
//             any of ( $tagasp_long* ) or
//             // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
//             any of ( $tagasp_classid* ) or
//             (
//                 $tagasp_short1 and
//                 $tagasp_short2 in ( filesize-100..filesize )
//             ) or (
//                 $tagasp_short2 and (
//                     $tagasp_short1 in ( 0..1000 ) or
//                     $tagasp_short1 in ( filesize-1000..filesize )
//                 )
//             )
//         ) and not (
//             (
//                 any of ( $perl* ) or
//                 $php1 at 0 or
//                 $php2 at 0
//             ) or (
//                 ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
//                 )
//         )
//         )
//         and any of ( $payload_and_input* ) ) or
//         ( filesize < 100 and any of ( $payload_and_input* ) )
// }

rule WEBSHELL_ASP_Nano
{
    meta:
        description = "Generic ASP webshell which uses any eval/exec function"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/13"
        modified = "2023-04-05"
        hash = "3b7910a499c603715b083ddb6f881c1a0a3a924d"
        hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
        hash = "22345e956bce23304f5e8e356c423cee60b0912c"
        hash = "c84a6098fbd89bd085526b220d0a3f9ab505bcba"
        hash = "b977c0ad20dc738b5dacda51ec8da718301a75d7"
        hash = "c69df00b57fd127c7d4e0e2a40d2f6c3056e0af8bfb1925938060b7e0d8c630f"
        hash = "f3b39a5da1cdde9acde077208e8e5b27feb973514dab7f262c7c6b2f8f11eaa7"
        hash = "0e9d92807d990144c637d8b081a6a90a74f15c7337522874cf6317092ea2d7c1"
        hash = "ebbc485e778f8e559ef9c66f55bb01dc4f5dcce9c31ccdd150e2c702c4b5d9e1"
        hash = "44b4068bfbbb8961e16bae238ad23d181ac9c8e4fcb4b09a66bbcd934d2d39ee"
        hash = "c5a4e188780b5513f34824904d56bf6e364979af6782417ccc5e5a8a70b4a95a"
        hash = "41a3cc668517ec207c990078bccfc877e239b12a7ff2abe55ff68352f76e819c"
        hash = "2faad5944142395794e5e6b90a34a6204412161f45e130aeb9c00eff764f65fc"
        hash = "d0c5e641120b8ea70a363529843d9f393074c54af87913b3ab635189fb0c84cb"
        hash = "28cfcfe28419a399c606bf96505bc68d6fe05624dba18306993f9fe0d398fbe1"

        id = "5f2f24c2-159d-51e1-80d9-11eeb77e8760"
    strings:
        $susasp1  = "/*-/*-*/"
        $susasp2  = "(\"%1"
        $susasp3  = /[Cc]hr\([Ss]tr\(/
        $susasp4  = "cmd.exe"
        $susasp5  = "cmd /c"
        $susasp7  = "FromBase64String"
        // Request and request in b64:
        $susasp8  = "UmVxdWVzdC"
        $susasp9  = "cmVxdWVzdA"
        $susasp10 = "/*//*/"
        $susasp11 = "(\"/*/\""
        $susasp12 = "eval(eval("
        $fp1      = "eval a"
        $fp2      = "'Eval'"
        $fp3      = "Eval(\""

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) and not any of ( $fp* ) and
        ( filesize < 200 or
        ( filesize < 1000 and any of ( $susasp* ) ) )
}

rule WEBSHELL_ASP_Encoded
{
    meta:
        description = "Webshell in VBscript or JScript encoded using *.Encode plus a suspicious string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "1bc7327f9d3dbff488e5b0b69a1b39dcb99b3399"
        hash = "9885ee1952b5ad9f84176c9570ad4f0e32461c92"
        hash = "27a020c5bc0dbabe889f436271df129627b02196"
        hash = "f41f8c82b155c3110fc1325e82b9ee92b741028b"
        hash = "af40f4c36e3723236c59dc02f28a3efb047d67dd"

        id = "67c0e1f6-6da5-569c-ab61-8b8607429471"
    strings:
        $encoded1 = "VBScript.Encode" nocase wide ascii
        $encoded2 = "JScript.Encode" nocase wide ascii
        $data1 = "#@~^" wide ascii
        $sus1 = "shell" nocase wide ascii
        $sus2 = "cmd" fullword wide ascii
        $sus3 = "password" fullword wide ascii
        $sus4 = "UserPass" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 500KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $encoded* ) and any of ( $data* ) and
        ( any of ( $sus* ) or
        ( filesize < 20KB and #data1 > 4 ) or
        ( filesize < 700 and #data1 > 0 ) )
}

rule WEBSHELL_ASP_Encoded_AspCoding
{
    meta:
        description = "ASP Webshell encoded using ASPEncodeDLL.AspCoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/14"
        modified = "2023-07-05"
        score = 60
        hash = "7cfd184ab099c4d60b13457140493b49c8ba61ee"
        hash = "f5095345ee085318235c11ae5869ae564d636a5342868d0935de7582ba3c7d7a"

        id = "788a8dae-bcb8-547c-ba17-e1f14bc28f34"
    strings:
        $encoded1 = "ASPEncodeDLL" fullword nocase wide ascii
        $encoded2 = ".Runt" nocase wide ascii
        $encoded3 = "Request" fullword nocase wide ascii
        $encoded4 = "Response" fullword nocase wide ascii
        $data1 = "AspCoding.EnCode" wide ascii
        //$sus1 = "shell" nocase wide ascii
        //$sus2 = "cmd" fullword wide ascii
        //$sus3 = "password" fullword wide ascii
        //$sus4 = "UserPass" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 500KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and all of ( $encoded* ) and any of ( $data* )
}

rule WEBSHELL_ASP_By_String
{
    meta:
        description = "Known ASP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021-01-13"
        modified = "2023-04-05"
        hash = "f72252b13d7ded46f0a206f63a1c19a66449f216"
        hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
        hash = "56a54fe1f8023455800fd0740037d806709ffb9ece1eb9e7486ad3c3e3608d45"
        hash = "4ef5d8b51f13b36ce7047e373159d7bb42ca6c9da30fad22e083ab19364c9985"
        hash = "e90c3c270a44575c68d269b6cf78de14222f2cbc5fdfb07b9995eb567d906220"
        hash = "8a38835f179e71111663b19baade78cc3c9e1f6fcc87eb35009cbd09393cbc53"
        hash = "f2883e9461393b33feed4139c0fc10fcc72ff92924249eb7be83cb5b76f0f4ee"
        hash = "10cca59c7112dfb1c9104d352e0504f842efd4e05b228b6f34c2d4e13ffd0eb6"
        hash = "ed179e5d4d365b0332e9ffca83f66ee0afe1f1b5ac3c656ccd08179170a4d9f7"
        hash = "ce3273e98e478a7e95fccce0a3d3e8135c234a46f305867f2deacd4f0efa7338"
        hash = "65543373b8bd7656478fdf9ceeacb8490ff8976b1fefc754cd35c89940225bcf"
        hash = "de173ea8dcef777368089504a4af0804864295b75e51794038a6d70f2bcfc6f5"


        id = "4705b28b-2ffa-53d1-b727-1a9fc2a7dd69"
    strings:
        // reversed
        $asp_string1  = "tseuqer lave" wide ascii
        $asp_string2  = ":eval request(" wide ascii
        $asp_string3  = ":eval request(" wide ascii
        $asp_string4  = "SItEuRl=\"http://www.zjjv.com\"" wide ascii
        $asp_string5  = "ServerVariables(\"HTTP_HOST\"),\"gov.cn\"" wide ascii
        // e+k-v+k-a+k-l
        // e+x-v+x-a+x-l
        $asp_string6  = /e\+.-v\+.-a\+.-l/ wide ascii
        $asp_string7  = "r+x-e+x-q+x-u" wide ascii
        $asp_string8  = "add6bb58e139be10" fullword wide ascii
        $asp_string9  = "WebAdmin2Y.x.y(\"" wide ascii
        $asp_string10 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[" wide ascii
        $asp_string11 = "<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request(" wide ascii
        // Request.Item["
        $asp_string12 = "UmVxdWVzdC5JdGVtWyJ" wide ascii

        // eval( in utf7 in base64 all 3 versions
        $asp_string13 = "UAdgBhAGwAKA" wide ascii
        $asp_string14 = "lAHYAYQBsACgA" wide ascii
        $asp_string15 = "ZQB2AGEAbAAoA" wide ascii
        // request in utf7 in base64 all 3 versions
        $asp_string16 = "IAZQBxAHUAZQBzAHQAKA" wide ascii
        $asp_string17 = "yAGUAcQB1AGUAcwB0ACgA" wide ascii
        $asp_string18 = "cgBlAHEAdQBlAHMAdAAoA" wide ascii

        $asp_string19 = "\"ev\"&\"al" wide ascii
        $asp_string20 = "\"Sc\"&\"ri\"&\"p" wide ascii
        $asp_string21 = "C\"&\"ont\"&\"" wide ascii
        $asp_string22 = "\"vb\"&\"sc" wide ascii
        $asp_string23 = "\"A\"&\"do\"&\"d" wide ascii
        $asp_string24 = "St\"&\"re\"&\"am\"" wide ascii
        $asp_string25 = "*/eval(" wide ascii
        $asp_string26 = "\"e\"&\"v\"&\"a\"&\"l" nocase
        $asp_string27 = "<%eval\"\"&(\"" nocase wide ascii
        $asp_string28 = "6877656D2B736972786677752B237E232C2A"  wide ascii
        $asp_string29 = "ws\"&\"cript.shell" wide ascii
        $asp_string30 = "SerVer.CreAtEoBjECT(\"ADODB.Stream\")" wide ascii
        $asp_string31 = "ASPShell - web based shell" wide ascii
        $asp_string32 = "<++ CmdAsp.asp ++>" wide ascii
        $asp_string33 = "\"scr\"&\"ipt\"" wide ascii
        $asp_string34 = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");" wide ascii
        $asp_string35 = "\"she\"&\"ll." wide ascii
        $asp_string36 = "LH\"&\"TTP" wide ascii
        $asp_string37 = "<title>Web Sniffer</title>" wide ascii
        $asp_string38 = "<title>WebSniff" wide ascii
        $asp_string39 = "cript\"&\"ing" wide ascii
        $asp_string40 = "tcejbOmetsySeliF.gnitpircS" wide ascii
        $asp_string41 = "tcejbOetaerC.revreS" wide ascii
        $asp_string42 = "This file is part of A Black Path Toward The Sun (\"ABPTTS\")" wide ascii
        $asp_string43 = "if ((Request.Headers[headerNameKey] != null) && (Request.Headers[headerNameKey].Trim() == headerValueKey.Trim()))" wide ascii
        $asp_string44 = "if (request.getHeader(headerNameKey).toString().trim().equals(headerValueKey.trim()))" wide ascii
        $asp_string45 = "Response.Write(Server.HtmlEncode(ExcutemeuCmd(txtArg.Text)));" wide ascii
        $asp_string46 = "\"c\" + \"m\" + \"d\"" wide ascii
        $asp_string47 = "\".\"+\"e\"+\"x\"+\"e\"" wide ascii
        $asp_string48 = "Tas9er" fullword wide ascii
        $asp_string49 = "<%@ Page Language=\"\\u" wide ascii
        $asp_string50 = "BinaryRead(\\u" wide ascii
        $asp_string51 = "Request.\\u" wide ascii
        $asp_string52 = "System.Buffer.\\u" wide ascii
        $asp_string53 = "System.Net.\\u" wide ascii
        $asp_string54 = ".\\u0052\\u0065\\u0066\\u006c\\u0065\\u0063\\u0074\\u0069\\u006f\\u006e\"" wide ascii
        $asp_string55 = "\\u0041\\u0073\\u0073\\u0065\\u006d\\u0062\\u006c\\u0079.\\u004c\\u006f\\u0061\\u0064" wide ascii
        $asp_string56 = "\\U00000052\\U00000065\\U00000071\\U00000075\\U00000065\\U00000073\\U00000074[\"" wide ascii
        $asp_string57 = "*/\\U0000" wide ascii
        $asp_string58 = "\\U0000FFFA" wide ascii
        $asp_string59 = "\"e45e329feb5d925b\"" wide ascii
        $asp_string60 = ">POWER!shelled<" wide ascii
        $asp_string61 = "@requires xhEditor" wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 200KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $asp_string* )
}

rule WEBSHELL_ASP_Sniffer
{
    meta:
        description = "ASP webshell which can sniff local traffic"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "1206c22de8d51055a5e3841b4542fb13aa0f97dd"
        hash = "60d131af1ed23810dbc78f85ee32ffd863f8f0f4"
        hash = "c3bc4ab8076ef184c526eb7f16e08d41b4cec97e"
        hash = "ed5938c04f61795834751d44a383f8ca0ceac833"

        id = "b5704c19-fce1-5210-8185-4839c1c5a344"
    strings:
        $sniff1 = "Socket(" wide ascii
        $sniff2 = ".Bind(" wide ascii
        $sniff3 = ".SetSocketOption(" wide ascii
        $sniff4 = ".IOControl(" wide ascii
        $sniff5 = "PacketCaptureWriter" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and filesize < 30KB and all of ( $sniff* )
}

rule WEBSHELL_ASP_Generic_Tiny
{
    meta:
        description = "Generic tiny ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
        hash = "52ce724580e533da983856c4ebe634336f5fd13a"
        hash = "0864f040a37c3e1cef0213df273870ed6a61e4bc"
        hash = "b184dc97b19485f734e3057e67007a16d47b2a62"

        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $fp1 = "net.rim.application.ipproxyservice.AdminCommand.execute"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and not 1 of ( $fp* ) and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and
        ( filesize < 700 and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) )
}

rule WEBSHELL_ASP_Generic : FILE {
    meta:
        description = "Generic ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021-03-07"
        modified = "2023-07-05"
        score = 60
        hash = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
        hash = "4cf6fbad0411b7d33e38075f5e00d4c8ae9ce2f6f53967729974d004a183b25c"
        hash = "a91320483df0178eb3cafea830c1bd94585fc896"
        hash = "f3398832f697e3db91c3da71a8e775ebf66c7e73"
        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $asp_much_sus7  = "Web Shell" nocase
        $asp_much_sus8  = "WebShell" nocase
        $asp_much_sus3  = "hidded shell"
        $asp_much_sus4  = "WScript.Shell.1" nocase
        $asp_much_sus5  = "AspExec"
        $asp_much_sus14 = "\\pcAnywhere\\" nocase
        $asp_much_sus15 = "antivirus" nocase
        $asp_much_sus16 = "McAfee" nocase
        $asp_much_sus17 = "nishang"
        $asp_much_sus18 = "\"unsafe" fullword wide ascii
        $asp_much_sus19 = "'unsafe" fullword wide ascii
        $asp_much_sus28 = "exploit" fullword wide ascii
        $asp_much_sus30 = "TVqQAAMAAA" wide ascii
        $asp_much_sus31 = "HACKED" fullword wide ascii
        $asp_much_sus32 = "hacked" fullword wide ascii
        $asp_much_sus33 = "hacker" wide ascii
        $asp_much_sus34 = "grayhat" nocase wide ascii
        $asp_much_sus35 = "Microsoft FrontPage" wide ascii
        $asp_much_sus36 = "Rootkit" wide ascii
        $asp_much_sus37 = "rootkit" wide ascii
        $asp_much_sus38 = "/*-/*-*/" wide ascii
        $asp_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $asp_much_sus40 = "\"e\"+\"v" wide ascii
        $asp_much_sus41 = "a\"+\"l\"" wide ascii
        $asp_much_sus42 = "\"+\"(\"+\"" wide ascii
        $asp_much_sus43 = "q\"+\"u\"" wide ascii
        $asp_much_sus44 = "\"u\"+\"e" wide ascii
        $asp_much_sus45 = "/*//*/" wide ascii
        $asp_much_sus46 = "(\"/*/\"" wide ascii
        $asp_much_sus47 = "eval(eval(" wide ascii
        $asp_much_sus48 = "Shell.Users" wide ascii
        $asp_much_sus49 = "PasswordType=Regular" wide ascii
        $asp_much_sus50 = "-Expire=0" wide ascii
        $asp_much_sus51 = "sh\"&\"el" wide ascii

        $asp_gen_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $asp_gen_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $asp_gen_sus6  = "self.delete"
        $asp_gen_sus9  = "\"cmd /c" nocase
        $asp_gen_sus10 = "\"cmd\"" nocase
        $asp_gen_sus11 = "\"cmd.exe" nocase
        $asp_gen_sus12 = "%comspec%" wide ascii
        $asp_gen_sus13 = "%COMSPEC%" wide ascii
        //TODO:$asp_gen_sus12 = ".UserName" nocase
        $asp_gen_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $asp_gen_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $asp_gen_sus21 = "\"upload\"" wide ascii
        $asp_gen_sus22 = "\"Upload\"" wide ascii
        $asp_gen_sus25 = "shell_" wide ascii
        //$asp_gen_sus26 = "password" fullword wide ascii
        //$asp_gen_sus27 = "passw" fullword wide ascii
        // own base64 or base 32 func
        $asp_gen_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $asp_gen_sus30 = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $asp_gen_sus31 = "serv-u" wide ascii
        $asp_gen_sus32 = "Serv-u" wide ascii
        $asp_gen_sus33 = "Army" fullword wide ascii

        $asp_slightly_sus1 = "<pre>" wide ascii
        $asp_slightly_sus2 = "<PRE>" wide ascii


        // "e"+"x"+"e"
        $asp_gen_obf1 = "\"+\"" wide ascii

        $fp1 = "DataBinder.Eval"
        $fp2 = "B2BTools"
        $fp3 = "<b>Failed to execute cache update. See the log file for more information" ascii
        $fp4 = "Microsoft. All rights reserved."

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = "Start" fullword wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

        //strings from private rule capa_asp_classid
        $tagasp_capa_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_capa_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_capa_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_capa_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_capa_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii

    condition:
        //any of them or
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        and not any of ( $fp* ) and
        ( ( filesize < 3KB and
        ( 1 of ( $asp_slightly_sus* ) ) ) or
        ( filesize < 25KB and
        ( 1 of ( $asp_much_sus* ) or 1 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 2 ) ) ) or
        ( filesize < 50KB and
        ( 1 of ( $asp_much_sus* ) or 3 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 6 ) ) ) or
        ( filesize < 150KB and
        ( 1 of ( $asp_much_sus* ) or 4 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 6 ) or
        ( (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        and
        ( 1 of ( $asp_much_sus* ) or 2 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 3 ) ) ) ) ) or
        ( filesize < 100KB and (
        any of ( $tagasp_capa_classid* )
        )
        ) )
}

rule WEBSHELL_ASP_Generic_Registry_Reader
{
    meta:
        description = "Generic ASP webshell which reads the registry (might look for passwords, license keys, database settings, general recon, ..."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/14"
        modified = "2023-07-05"
        score = 50
        hash = "4d53416398a89aef3a39f63338a7c1bf2d3fcda4"
        hash = "f85cf490d7eb4484b415bea08b7e24742704bdda"
        hash = "898ebfa1757dcbbecb2afcdab1560d72ae6940de"

        id = "02d6f95f-1801-5fb0-8ab8-92176cf2fdd7"
    strings:
        /* $asp_reg1  = "Registry" fullword wide ascii */ /* too many matches issues */
        $asp_reg2  = "LocalMachine" fullword wide ascii
        $asp_reg3  = "ClassesRoot" fullword wide ascii
        $asp_reg4  = "CurrentUser" fullword wide ascii
        $asp_reg5  = "Users" fullword wide ascii
        $asp_reg6  = "CurrentConfig" fullword wide ascii
        $asp_reg7  = "Microsoft.Win32" fullword wide ascii
        $asp_reg8  = "OpenSubKey" fullword wide ascii

        $sus1 = "shell" fullword nocase wide ascii
        $sus2 = "cmd.exe" fullword wide ascii
        $sus3 = "<form " wide ascii
        $sus4 = "<table " wide ascii
        $sus5 = "System.Security.SecurityException" wide ascii

        $fp1 = "Avira Operations GmbH" wide

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and all of ( $asp_reg* ) and any of ( $sus* ) and not any of ( $fp* ) and
        ( filesize < 10KB or
        ( filesize < 150KB and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        ) )
}

rule WEBSHELL_ASPX_Regeorg_CSHARP
{
    meta:
        description = "Webshell regeorg aspx c# version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "c1f43b7cf46ba12cfc1357b17e4f5af408740af7ae70572c9cf988ac50260ce1"
        author = "Arnim Rupp (https://github.com/ruppde)"
        score = 75
        date = "2021/01/11"
        modified = "2023-07-05"
        hash = "479c1e1f1c263abe339de8be99806c733da4e8c1"
        hash = "38a1f1fc4e30c0b4ad6e7f0e1df5a92a7d05020b"
        hash = "e54f1a3eab740201feda235835fc0aa2e0c44ba9"
        hash = "aea0999c6e5952ec04bf9ee717469250cddf8a6f"

        id = "0a53d368-5f1b-55b7-b08f-36b0f8c5612f"
    strings:
        $input_sa1 = "Request.QueryString.Get" fullword nocase wide ascii
        $input_sa2 = "Request.Headers.Get" fullword nocase wide ascii
        $sa1 = "AddressFamily.InterNetwork" fullword nocase wide ascii
        $sa2 = "Response.AddHeader" fullword nocase wide ascii
        $sa3 = "Request.InputStream.Read" nocase wide ascii
        $sa4 = "Response.BinaryWrite" nocase wide ascii
        $sa5 = "Socket" nocase wide ascii
        $georg = "Response.Write(\"Georg says, 'All seems fine'\")"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 300KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( $georg or
        ( all of ( $sa* ) and any of ( $input_sa* ) ) )
}

rule WEBSHELL_CSHARP_Generic
{
    meta:
        description = "Webshell in c#"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "b6721683aadc4b4eba4f081f2bc6bc57adfc0e378f6d80e2bfa0b1e3e57c85c7"
        date = "2021/01/11"
        modified = "2023-07-05"
        hash = "4b365fc9ddc8b247a12f4648cd5c91ee65e33fae"
        hash = "019eb61a6b5046502808fb5ab2925be65c0539b4"
        hash = "620ee444517df8e28f95e4046cd7509ac86cd514"
        hash = "a91320483df0178eb3cafea830c1bd94585fc896"

        id = "6d38a6b0-b1d2-51b0-9239-319f1fea7cae"
    strings:
        $input_http = "Request." nocase wide ascii
        $input_form1 = "<asp:" nocase wide ascii
        $input_form2 = ".text" nocase wide ascii
        $exec_proc1 = "new Process" nocase wide ascii
        $exec_proc2 = "start(" nocase wide ascii
        $exec_shell1 = "cmd.exe" nocase wide ascii
        $exec_shell2 = "powershell.exe" nocase wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and filesize < 300KB and
        ( $input_http or all of ( $input_form* ) ) and all of ( $exec_proc* ) and any of ( $exec_shell* )
}

import "pe"
rule WEBSHELL_ASP_Runtime_Compile : FILE {
    meta:
        description = "ASP webshell compiling payload in memory at runtime, e.g. sharpyshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "https://github.com/antonioCoco/SharPyShell"
        date = "2021/01/11"
        modified = "2023-04-05"
        score = 75
        hash = "e826c4139282818d38dcccd35c7ae6857b1d1d01"
        hash = "e20e078d9fcbb209e3733a06ad21847c5c5f0e52"
        hash = "57f758137aa3a125e4af809789f3681d1b08ee5b"
        hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
        hash = "e44058dd1f08405e59d411d37d2ebc3253e2140385fa2023f9457474031b48ee"
        hash = "f6092ab5c8d491ae43c9e1838c5fd79480055033b081945d16ff0f1aaf25e6c7"
        hash = "dfd30139e66cba45b2ad679c357a1e2f565e6b3140a17e36e29a1e5839e87c5e"
        hash = "89eac7423dbf86eb0b443d8dd14252b4208e7462ac2971c99f257876388fccf2"
        hash = "8ce4eaf111c66c2e6c08a271d849204832713f8b66aceb5dadc293b818ccca9e"
        id = "5da9318d-f542-5603-a111-5b240f566d47"
    strings:
        $payload_reflection1 = "System" fullword nocase wide ascii
        $payload_reflection2 = "Reflection" fullword nocase wide ascii
        $payload_reflection3 = "Assembly" fullword nocase wide ascii
        $payload_load_reflection1 = /[."']Load\b/ nocase wide ascii
        // only match on "load" or variable which might contain "load"
        $payload_load_reflection2 = /\bGetMethod\(("load|\w)/ nocase wide ascii
        $payload_compile1 = "GenerateInMemory" nocase wide ascii
        $payload_compile2 = "CompileAssemblyFromSource" nocase wide ascii
        $payload_invoke1 = "Invoke" fullword nocase wide ascii
        $payload_invoke2 = "CreateInstance" fullword nocase wide ascii
        $payload_xamlreader1 = "XamlReader" fullword nocase wide ascii
        $payload_xamlreader2 = "Parse" fullword nocase wide ascii
        $payload_xamlreader3 = "assembly=" nocase wide ascii
        $payload_powershell1 = "PSObject" fullword nocase wide ascii
        $payload_powershell2 = "Invoke" fullword nocase wide ascii
        $payload_powershell3 = "CreateRunspace" fullword nocase wide ascii
        $rc_fp1 = "Request.MapPath"
        $rc_fp2 = "<body><mono:MonoSamplesHeader runat=\"server\"/>" wide ascii

        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_input4 = "\\u0065\\u0071\\u0075" wide ascii // equ of Request
        $asp_input5 = "\\u0065\\u0073\\u0074" wide ascii // est of Request
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        $sus_refl1 = " ^= " wide ascii
        $sus_refl2 = "SharPy" wide ascii

    condition:
        //any of them or
        not pe.is_pe and
        (
            (
                filesize < 50KB and
                any of ( $sus_refl* )
            ) or
            filesize < 10KB
        ) and
        (
                any of ( $asp_input* ) or
            (
                $asp_xml_http and
                any of ( $asp_xml_method* )
            ) or
            (
                any of ( $asp_form* ) and
                any of ( $asp_text* ) and
                $asp_asp
            )
        )
        and not any of ( $rc_fp* ) and
        (
            (
                all of ( $payload_reflection* ) and
                any of ( $payload_load_reflection* )
            )
            or
            (
                all of ( $payload_compile* ) and
                any of ( $payload_invoke* )
            )
            or all of ( $payload_xamlreader* )
            or all of ( $payload_powershell* )
        )
}

rule WEBSHELL_ASP_SQL
{
    meta:
        description = "ASP webshell giving SQL access. Might also be a dual use tool."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "216c1dd950e0718e35bc4834c5abdc2229de3612"
        hash = "ffe44e9985d381261a6e80f55770833e4b78424bn"
        hash = "3d7cd32d53abc7f39faed133e0a8f95a09932b64"
        hash = "f19cc178f1cfad8601f5eea2352cdbd2d6f94e7e"
        hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"

        id = "e534dcb9-40ab-544f-ae55-89fb21c422e9"
    strings:
        $sql1 = "SqlConnection" fullword wide ascii
        $sql2 = "SQLConnection" fullword wide ascii
        $sql3 = "System" fullword wide ascii
        $sql4 = "Data" fullword wide ascii
        $sql5 = "SqlClient" fullword wide ascii
        $sql6 = "SQLClient" fullword wide ascii
        $sql7 = "Open" fullword wide ascii
        $sql8 = "SqlCommand" fullword wide ascii
        $sql9 = "SQLCommand" fullword wide ascii

        $o_sql1 = "SQLOLEDB" fullword wide ascii
        $o_sql2 = "CreateObject" fullword wide ascii
        $o_sql3 = "open" fullword wide ascii

        $a_sql1 = "ADODB.Connection" fullword wide ascii
        $a_sql2 = "adodb.connection" fullword wide ascii
        $a_sql3 = "CreateObject" fullword wide ascii
        $a_sql4 = "createobject" fullword wide ascii
        $a_sql5 = "open" fullword wide ascii

        $c_sql1 = "System.Data.SqlClient" fullword wide ascii
        $c_sql2 = "sqlConnection" fullword wide ascii
        $c_sql3 = "open" fullword wide ascii

        $sus1 = "shell" fullword nocase wide ascii
        $sus2 = "xp_cmdshell" fullword nocase wide ascii
        $sus3 = "aspxspy" fullword nocase wide ascii
        $sus4 = "_KillMe" wide ascii
        $sus5 = "cmd.exe" fullword wide ascii
        $sus6 = "cmd /c" fullword wide ascii
        $sus7 = "net user" fullword wide ascii
        $sus8 = "\\x2D\\x3E\\x7C" wide ascii
        $sus9 = "Hacker" fullword wide ascii
        $sus10 = "hacker" fullword wide ascii
        $sus11 = "HACKER" fullword wide ascii
        $sus12 = "webshell" wide ascii
        $sus13 = "equest[\"sql\"]" wide ascii
        $sus14 = "equest(\"sql\")" wide ascii
        $sus15 = { e5 bc 80 e5 a7 8b e5 af bc e5 }
        $sus16 = "\"sqlCommand\"" wide ascii
        $sus17 = "\"sqlcommand\"" wide ascii

        //$slightly_sus1 = "select * from " wide ascii
        //$slightly_sus2 = "SELECT * FROM " wide ascii
        $slightly_sus3 = "SHOW COLUMNS FROM " wide ascii
        $slightly_sus4 = "show columns from " wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and
        ( 6 of ( $sql* ) or all of ( $o_sql* ) or 3 of ( $a_sql* ) or all of ( $c_sql* ) ) and
        ( ( filesize < 150KB and any of ( $sus* ) ) or
        ( filesize < 5KB and any of ( $slightly_sus* ) ) )
}

rule WEBSHELL_ASP_Scan_Writable
{
    meta:
        description = "ASP webshell searching for writable directories (to hide more webshells ...)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-04-05"
        hash = "2409eda9047085baf12e0f1b9d0b357672f7a152"
        hash = "af1c00696243f8b062a53dad9fb8b773fa1f0395631ffe6c7decc42c47eedee7"

        id = "1766e081-0591-59ab-b546-b13207764b4d"
    strings:
        $scan1 = "DirectoryInfo" nocase fullword wide ascii
        $scan2 = "GetDirectories" nocase fullword wide ascii
        $scan3 = "Create" nocase fullword wide ascii
        $scan4 = "File" nocase fullword wide ascii
        $scan5 = "System.IO" nocase fullword wide ascii
        // two methods: check permissions or write and delete:
        $scan6 = "CanWrite" nocase fullword wide ascii
        $scan7 = "Delete" nocase fullword wide ascii


        $sus1 = "upload" nocase fullword wide ascii
        $sus2 = "shell" nocase wide ascii
        $sus3 = "orking directory" nocase fullword wide ascii
        $sus4 = "scan" nocase wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        filesize < 10KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and 6 of ( $scan* ) and any of ( $sus* )
}

rule WEBSHELL_JSP_ReGeorg
{
    meta:
        description = "Webshell regeorg JSP version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2023-04-05"
        score = 75
        hash = "650eaa21f4031d7da591ebb68e9fc5ce5c860689"
        hash = "00c86bf6ce026ccfaac955840d18391fbff5c933"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        hash = "9108a33058aa9a2fb6118b719c5b1318f33f0989"

        id = "cbb90005-d8f8-5c64-85d1-29e466f48c25"
    strings:
        $jgeorg1 = "request" fullword wide ascii
        $jgeorg2 = "getHeader" fullword wide ascii
        $jgeorg3 = "X-CMD" fullword wide ascii
        $jgeorg4 = "X-STATUS" fullword wide ascii
        $jgeorg5 = "socket" fullword wide ascii
        $jgeorg6 = "FORWARD" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        filesize < 300KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and all of ( $jgeorg* )
}

rule WEBSHELL_JSP_HTTP_Proxy
{
    meta:
        description = "Webshell JSP HTTP proxy"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2023-07-05"
        hash = "97c1e2bf7e769d3fc94ae2fc74ac895f669102c6"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"

        id = "55be246e-30a8-52ed-bc5f-507e63bbfe16"
    strings:
        $jh1 = "OutputStream" fullword wide ascii
        $jh2 = "InputStream"  wide ascii
        $jh3 = "BufferedReader" fullword wide ascii
        $jh4 = "HttpRequest" fullword wide ascii
        $jh5 = "openConnection" fullword wide ascii
        $jh6 = "getParameter" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        filesize < 10KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and all of ( $jh* )
}

rule WEBSHELL_JSP_Writer_Nano
{
    meta:
        description = "JSP file writer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "ac91e5b9b9dcd373eaa9360a51aa661481ab9429"
        hash = "c718c885b5d6e29161ee8ea0acadb6e53c556513"
        hash = "9f1df0249a6a491cdd5df598d83307338daa4c43"
        hash = "5e241d9d3a045d3ade7b6ff6af6c57b149fa356e"

        id = "422a18f2-d6d4-5b42-be15-1eafe44e01cf"
    strings:
        // writting file to disk
        $payload1 = ".write" wide ascii
        $payload2 = "getBytes" fullword wide ascii
        $payload3 = ".decodeBuffer" wide ascii
        $payload4 = "FileOutputStream" fullword wide ascii

        // writting using java logging, e.g 9f1df0249a6a491cdd5df598d83307338daa4c43
        $logger1 = "getLogger" fullword ascii wide
        $logger2 = "FileHandler" fullword ascii wide
        $logger3 = "addHandler" fullword ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        $jw_sus1 = /getParameter\("."\)/ ascii wide // one char param
        $jw_sus4 = "yoco" fullword ascii wide // webshell coder

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        //any of them or
        (
            any of ( $input* ) and
            any of ( $req* )
        ) and (
            filesize < 200 or
            (
                filesize < 1000 and
                any of ( $jw_sus* )
            )
        )
        and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            2 of ( $payload* ) or
            all of ( $logger* )
            )
}

rule WEBSHELL_JSP_Generic_Tiny
{
    meta:
        description = "Generic JSP webshell tiny"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "8fd343db0442136e693e745d7af1018a99b042af"
        hash = "87c3ac9b75a72187e8bc6c61f50659435dbdc4fde6ed720cebb93881ba5989d8"
        hash = "1aa6af726137bf261849c05d18d0a630d95530588832aadd5101af28acc034b5"

        id = "7535ade8-fc65-5558-a72c-cc14c3306390"
    strings:
        $payload1 = "ProcessBuilder" fullword wide ascii
        $payload2 = "URLClassLoader" fullword wide ascii
        // Runtime.getRuntime().exec(
        $payload_rt1 = "Runtime" fullword wide ascii
        $payload_rt2 = "getRuntime" fullword wide ascii
        $payload_rt3 = "exec" fullword wide ascii

        $jg_sus1 = "xe /c" ascii wide // of cmd.exe /c
        $jg_sus2 = /getParameter\("."\)/ ascii wide // one char param
        $jg_sus3 = "</pre>" ascii wide // webshells like fixed font wide
        $jg_sus4 = "BASE64Decoder" fullword ascii wide

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        // no web input but fixed command to create reverse shell
        $fixed_cmd1 = "bash -i >& /dev/" ascii wide

    condition:
        //any of them or
        (
            (
                filesize < 1000 and
                any of ( $jg_sus* )
            ) or
            filesize < 250
        ) and (
            $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
                (
                    any of ( $input* ) and
                    any of ( $req* )
                ) or (
                    any of ( $fixed_cmd* )
                )
        )
        and
        ( 1 of ( $payload* ) or all of ( $payload_rt* ) )
}

rule WEBSHELL_JSP_Generic
{
    meta:
        description = "Generic JSP webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "4762f36ca01fb9cda2ab559623d2206f401fc0b1"
        hash = "bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1"
        hash = "ee9408eb923f2d16f606a5aaac7e16b009797a07"

        id = "7535ade8-fc65-5558-a72c-cc14c3306390"
    strings:
        $susp0 = "cmd" fullword nocase ascii wide
        $susp1 = "command" fullword nocase ascii wide
        $susp2 = "shell" fullword nocase ascii wide
        $susp3 = "download" fullword nocase ascii wide
        $susp4 = "upload" fullword nocase ascii wide
        $susp5 = "Execute" fullword nocase ascii wide
        $susp6 = "\"pwd\"" ascii wide
        $susp7 = "\"</pre>" ascii wide
        $susp8 = /\\u00\d\d\\u00\d\d\\u00\d\d\\u00\d\d/ ascii wide
        $susp9 = "*/\\u00" ascii wide // perfect match of 2 obfuscation methods: /**/\u00xx :)

        $fp1 = "command = \"cmd.exe /c set\";"

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii wide
        $payload2 = "processCmd" fullword ascii wide
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii wide
        $rt_payload2 = "getRuntime" fullword ascii wide
        $rt_payload3 = "exec" fullword ascii wide

    condition:
        filesize < 300KB and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and (
        1 of ( $payload* ) or
        all of ( $rt_payload* )
        )
        and not any of ( $fp* ) and any of ( $susp* )
}

rule WEBSHELL_JSP_Generic_Base64
{
    meta:
        description = "Generic JSP webshell with base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "8b5fe53f8833df3657ae2eeafb4fd101c05f0db0"
        hash = "1b916afdd415dfa4e77cecf47321fd676ba2184d"

        id = "2eabbad2-7d10-573a-9120-b9b763fa2352"
    strings:
        // Runtime
        $one1 = "SdW50aW1l" wide ascii
        $one2 = "J1bnRpbW" wide ascii
        $one3 = "UnVudGltZ" wide ascii
        $one4 = "IAdQBuAHQAaQBtAGUA" wide ascii
        $one5 = "SAHUAbgB0AGkAbQBlA" wide ascii
        $one6 = "UgB1AG4AdABpAG0AZQ" wide ascii
        // exec
        $two1 = "leGVj" wide ascii
        $two2 = "V4ZW" wide ascii
        $two3 = "ZXhlY" wide ascii
        $two4 = "UAeABlAGMA" wide ascii
        $two5 = "lAHgAZQBjA" wide ascii
        $two6 = "ZQB4AGUAYw" wide ascii
        // ScriptEngineFactory
        $three1 = "TY3JpcHRFbmdpbmVGYWN0b3J5" wide ascii
        $three2 = "NjcmlwdEVuZ2luZUZhY3Rvcn" wide ascii
        $three3 = "U2NyaXB0RW5naW5lRmFjdG9ye" wide ascii
        $three4 = "MAYwByAGkAcAB0AEUAbgBnAGkAbgBlAEYAYQBjAHQAbwByAHkA" wide ascii
        $three5 = "TAGMAcgBpAHAAdABFAG4AZwBpAG4AZQBGAGEAYwB0AG8AcgB5A" wide ascii
        $three6 = "UwBjAHIAaQBwAHQARQBuAGcAaQBuAGUARgBhAGMAdABvAHIAeQ" wide ascii


        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and filesize < 300KB and
        ( any of ( $one* ) and any of ( $two* ) or any of ( $three* ) )
}

rule WEBSHELL_JSP_Generic_ProcessBuilder
{
    meta:
        description = "Generic JSP webshell which uses processbuilder to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "82198670ac2072cd5c2853d59dcd0f8dfcc28923"
        hash = "c05a520d96e4ebf9eb5c73fc0fa446ceb5caf343"
        hash = "347a55c174ee39ec912d9107e971d740f3208d53af43ea480f502d177106bbe8"
        hash = "d0ba29b646274e8cda5be1b940a38d248880d9e2bba11d994d4392c80d6b65bd"

        id = "2a7c5f44-24a1-5f43-996e-945c209b79b1"
    strings:
        $exec = "ProcessBuilder" fullword wide ascii
        $start = "start" fullword wide ascii

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 2000 and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and $exec and $start
}

rule WEBSHELL_JSP_Generic_Reflection
{
    meta:
        description = "Generic JSP webshell which uses reflection to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
        hash = "bf0ff88cbb72c719a291c722ae3115b91748d5c4920afe7a00a0d921d562e188"

        id = "806ffc8b-1dc8-5e28-ae94-12ad3fee18cd"
    strings:
        $ws_exec = "invoke" fullword wide ascii
        $ws_class = "Class" fullword wide ascii
        $fp = "SOAPConnection"

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        $cj_encoded1 = "\"java.util.Base64$Decoder\"" ascii wide
    condition:
        //any of them or
        all of ( $ws_* ) and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not $fp and
        (
            // either some kind of code input from the a web request ...
            filesize < 10KB and
            (
                any of ( $input* ) and
                any of ( $req* )
            )
            or
            (
                // ... or some encoded payload (which might get code input from a web request)
                filesize < 30KB and
                any of ( $cj_encoded* ) and
                // base64 :
                // ignore first and last 500bytes because they usually contain code for decoding and executing
                math.entropy(500, filesize-500) >= 5.5 and
                // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                math.mean(500, filesize-500) > 80 and
                // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                // 89 is the mean of the base64 chars
                math.deviation(500, filesize-500, 89.0) < 23
            )
        )

}

// rule WEBSHELL_JSP_Generic_Classloader
// {
//     meta:
//         description = "Generic JSP webshell which uses classloader to execute user input"
//         license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
//         author = "Arnim Rupp (https://github.com/ruppde)"
//         reference = "Internal Research"
//         score = 75
//         hash = "6b546e78cc7821b63192bb8e087c133e8702a377d17baaeb64b13f0dd61e2347"
//         date = "2021/01/07"
//         modified = "2023-04-05"
//         hash = "f3a7e28e1c38fa5d37811bdda1d6b0893ab876023d3bd696747a35c04141dcf0"
//         hash = "8ea2a25344e6094fa82dfc097bbec5f1675f6058f2b7560deb4390bcbce5a0e7"
//         hash = "b9ea1e9f91c70160ee29151aa35f23c236d220c72709b2b75123e6fa1da5c86c"
//         hash = "80211c97f5b5cd6c3ab23ae51003fd73409d273727ba502d052f6c2bd07046d6"
//         hash = "8e544a5f0c242d1f7be503e045738369405d39731fcd553a38b568e0889af1f2"
// 
//         id = "037e6b24-9faf-569b-bb52-dbe671ab2e87"
//     strings:
//         $exec = "extends ClassLoader" wide ascii
//         $class = "defineClass" fullword wide ascii
// 
//         //strings from private rule capa_jsp_safe
//         $cjsp_short1 = "<%" ascii wide
//         $cjsp_short2 = "%>" wide ascii
//         $cjsp_long1 = "<jsp:" ascii wide
//         $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
//         // JSF
//         $cjsp_long3 = "/jstl/core" ascii wide
//         $cjsp_long4 = "<%@p" nocase ascii wide
//         $cjsp_long5 = "<%@ " nocase ascii wide
//         $cjsp_long6 = "<% " ascii wide
//         $cjsp_long7 = "< %" ascii wide
// 
//         //strings from private rule capa_jsp_input
//         // request.getParameter
//         $input1 = "getParameter" fullword ascii wide
//         // request.getHeaders
//         $input2 = "getHeaders" fullword ascii wide
//         $input3 = "getInputStream" fullword ascii wide
//         $input4 = "getReader" fullword ascii wide
//         $req1 = "request" fullword ascii wide
//         $req2 = "HttpServletRequest" fullword ascii wide
//         $req3 = "getRequest" fullword ascii wide
// 
//     condition:
//         //any of them or
//         (
//             (
//                 $cjsp_short1 at 0 or
//                     any of ( $cjsp_long* ) or
//                     $cjsp_short2 in ( filesize-100..filesize ) or
//                 (
//                     $cjsp_short2 and (
//                         $cjsp_short1 in ( 0..1000 ) or
//                         $cjsp_short1 in ( filesize-1000..filesize )
//                     )
//                 )
//             )
//             and (
//                 any of ( $input* ) and
//                 any of ( $req* )
//             )
//             and $exec and $class
//         ) and
//         (
//             filesize < 10KB or
//             (
//                 filesize < 50KB and
//                 (
//                     // filled with same characters
//                     math.entropy(500, filesize-500) <= 1 or
//                     // filled with random garbage
//                     math.entropy(500, filesize-500) >= 7.7
//                 )
//             )
//         )
// }

rule WEBSHELL_JSP_Generic_Encoded_Shell
{
    meta:
        description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "3eecc354390d60878afaa67a20b0802ce5805f3a9bb34e74dd8c363e3ca0ea5c"
        hash = "f6c2112e3a25ec610b517ff481675b2ce893cb9f"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"

        id = "359949d7-1793-5e13-9fdc-fe995ae12117"
    strings:
        $sj0 = /{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
        $sj1 = /{ ?99, 109, 100}/ wide ascii
        $sj2 = /{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
        $sj3 = /{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
        $sj4 = /{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
        $sj5 = /{ ?101, 120, 101, 99 }/ wide ascii
        $sj6 = /{ ?103, 101, 116, 82, 117, 110/ wide ascii

    condition:
        filesize <300KB and any of ($sj*)
}

rule WEBSHELL_JSP_NetSpy
{
    meta:
        description = "JSP netspy webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "94d1aaabde8ff9b4b8f394dc68caebf981c86587"
        hash = "3870b31f26975a7cb424eab6521fc9bffc2af580"

        id = "41f5c171-878d-579f-811d-91d74f7e3e24"
    strings:
        $scan1 = "scan" nocase wide ascii
        $scan2 = "port" nocase wide ascii
        $scan3 = "web" fullword nocase wide ascii
        $scan4 = "proxy" fullword nocase wide ascii
        $scan5 = "http" fullword nocase wide ascii
        $scan6 = "https" fullword nocase wide ascii
        $write1 = "os.write" fullword wide ascii
        $write2 = "FileOutputStream" fullword wide ascii
        $write3 = "PrintWriter" fullword wide ascii
        $http = "java.net.HttpURLConnection" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 30KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and 4 of ( $scan* ) and 1 of ( $write* ) and $http
}

rule WEBSHELL_JSP_By_String
{
    meta:
        description = "JSP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/09"
        modified = "2023-04-05"
        hash = "e9060aa2caf96be49e3b6f490d08b8a996c4b084"
        hash = "4c2464503237beba54f66f4a099e7e75028707aa"
        hash = "06b42d4707e7326aff402ecbb585884863c6351a"
        hash = "dada47c052ec7fcf11d5cfb25693bc300d3df87de182a254f9b66c7c2c63bf2e"
        hash = "f9f6c696c1f90df6421cd9878a1dec51a62e91b4b4f7eac4920399cb39bc3139"
        hash = "f1d8360dc92544cce301949e23aad6eb49049bacf9b7f54c24f89f7f02d214bb"
        hash = "1d1f26b1925a9d0caca3fdd8116629bbcf69f37f751a532b7096a1e37f4f0076"
        hash = "850f998753fde301d7c688b4eca784a045130039512cf51292fcb678187c560b"

        id = "8d64e40b-5583-5887-afe1-b926d9880913"
    strings:
        $jstring1 = "<title>Boot Shell</title>" wide ascii
        $jstring2 = "String oraPWD=\"" wide ascii
        $jstring3 = "Owned by Chinese Hackers!" wide ascii
        $jstring4 = "AntSword JSP" wide ascii
        $jstring5 = "JSP Webshell</" wide ascii
        $jstring6 = "motoME722remind2012" wide ascii
        $jstring7 = "EC(getFromBase64(toStringHex(request.getParameter(\"password" wide ascii
        $jstring8 = "http://jmmm.com/web/index.jsp" wide ascii
        $jstring9 = "list.jsp = Directory & File View" wide ascii
        $jstring10 = "jdbcRowSet.setDataSourceName(request.getParameter(" wide ascii
        $jstring11 = "Mr.Un1k0d3r RingZer0 Team" wide ascii
        $jstring12 = "MiniWebCmdShell" fullword wide ascii
        $jstring13 = "pwnshell.jsp" fullword wide ascii
        $jstring14 = "session set &lt;key&gt; &lt;value&gt; [class]<br>"  wide ascii
        $jstring15 = "Runtime.getRuntime().exec(request.getParameter(" nocase wide ascii
        $jstring16 = "GIF98a<%@page" wide ascii
        $jstring17 = "Tas9er" fullword wide ascii
        $jstring18 = "uu0028\\u" wide ascii //obfuscated /
        $jstring19 = "uu0065\\u" wide ascii //obfuscated e
        $jstring20 = "uu0073\\u" wide ascii //obfuscated s
        $jstring21 = /\\uuu{0,50}00/ wide ascii //obfuscated via javas unlimited amount of u in \uuuuuu
        $jstring22 = /[\w\.]\\u(FFFB|FEFF|FFF9|FFFA|200C|202E|202D)[\w\.]/ wide ascii // java ignores the unicode Interlinear Annotation Terminator inbetween any command
        $jstring23 = "\"e45e329feb5d925b\"" wide ascii
        $jstring24 = "u<![CDATA[n" wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        //any of them or
        not (
            uint16(0) == 0x5a4d or
            $dex at 0 or
            $pack at 0 or
            // fp on jar with zero compression
            uint16(0) == 0x4b50
        ) and
        (
            (
                filesize < 100KB and
                (
                    $cjsp_short1 at 0 or
                    any of ( $cjsp_long* ) or
                    $cjsp_short2 in ( filesize-100..filesize ) or
                    (
                        $cjsp_short2 and (
                            $cjsp_short1 in ( 0..1000 ) or
                            $cjsp_short1 in ( filesize-1000..filesize )
                        )
                    )
                )
                and any of ( $jstring* )
            ) or (
                filesize < 500KB and
                (
                    #jstring21 > 20 or
                    $jstring18 or
                    $jstring19 or
                    $jstring20

                )
            )
        )
}

rule WEBSHELL_JSP_Input_Upload_Write
{
    meta:
        description = "JSP uploader which gets input, writes files and contains upload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "ef98ca135dfb9dcdd2f730b18e883adf50c4ab82"
        hash = "583231786bc1d0ecca7d8d2b083804736a3f0a32"
        hash = "19eca79163259d80375ebebbc440b9545163e6a3"

        id = "bbf26edd-88b7-5ec5-a16e-d96a086dcd19"
    strings:
        $upload = "upload" nocase wide ascii
        $write1 = "os.write" fullword wide ascii
        $write2 = "FileOutputStream" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 10KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and $upload and 1 of ( $write* )
}

rule WEBSHELL_Generic_OS_Strings : FILE {
    meta:
        description = "typical webshell strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/12"
        modified = "2023-07-05"
        score = 50
        hash = "d5bfe40283a28917fcda0cefd2af301f9a7ecdad"
        hash = "fd45a72bda0a38d5ad81371d68d206035cb71a14"
        hash = "b4544b119f919d8cbf40ca2c4a7ab5c1a4da73a3"
        hash = "569259aafe06ba3cef9e775ee6d142fed6edff5f"
        hash = "48909d9f4332840b4e04b86f9723d7427e33ac67"
        hash = "0353ae68b12b8f6b74794d3273967b530d0d526f"
        id = "ea85e415-4774-58ac-b063-0f5eb535ec49"
    strings:
        $fp1 = "http://evil.com/" wide ascii
        $fp2 = "denormalize('/etc/shadow" wide ascii
        $fp3 = "vim.org>"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_os_strings
        // windows = nocase
        $w1 = "net localgroup administrators" nocase wide ascii
        $w2 = "net user" nocase wide ascii
        $w3 = "/add" nocase wide ascii
        // linux stuff, case sensitive:
        $l1 = "/etc/shadow" wide ascii
        $l2 = "/etc/ssh/sshd_config" wide ascii
        $take_two1 = "net user" nocase wide ascii
        $take_two2 = "/add" nocase wide ascii

    condition:
        filesize < 70KB and
        ( (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        or (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        or (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        ) and (
            filesize < 300KB and
        not uint16(0) == 0x5a4d and (
            all of ( $w* ) or
            all of ( $l* ) or
            2 of ( $take_two* )
        )
        )
        and not any of ( $fp* )
}

rule WEBSHELL_In_Image
{
    meta:
        description = "Webshell in GIF, PNG or JPG"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        hash = "d4fde4e691db3e70a6320e78657480e563a9f87935af873a99db72d6a9a83c78"
        hash = "84938133ee6e139a2816ab1afc1c83f27243c8ae76746ceb2e7f20649b5b16a4"
        hash = "52b918a64afc55d28cd491de451bb89c57bce424f8696d6a94ec31fb99b17c11"
        date = "2021/02/27"
        modified = "2023-04-05"
        score = 75

        id = "b1185b69-9b08-5925-823a-829fee6fa4cf"
    strings:
        $png = { 89 50 4E 47 }
        $jpg = { FF D8 FF E0 }
        $gif = "GIF8" wide ascii // doesn't make sense for a GIF but some webshells are utf8 :)
        $gif2 = "gif89" // not a valid gif but used in webshells
        $gif3 = "Gif89" // not a valid gif but used in webshells
        // MS access
        $mdb = { 00 01 00 00 53 74 }
        //$mdb = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" wide ascii
        $php_multi_write2 = "fwrite(" wide ascii
        $php_write1 = "move_uploaded_file" fullword wide ascii

        //strings from private rule capa_jsp
        $cjsp1 = "<%" ascii wide
        $cjsp2 = "<jsp:" ascii wide
        $cjsp3 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp4 = "/jstl/core" ascii wide

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii wide
        $payload2 = "processCmd" fullword ascii wide
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii wide
        $rt_payload2 = "getRuntime" fullword ascii wide
        $rt_payload3 = "exec" fullword ascii wide

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        // reduce fp
        //any of them or
        filesize < 5MB and
        // also check for GIF8 at 0x3 because some folks write their webshell in a text editor and have a BOM in front of GIF8 (which probably wouldn't be a valif GIF anymore :)
        ( $png at 0 or $jpg at 0 or $gif at 0 or $gif at 3 or $gif2 at 0 or $gif2 at 3 or $gif3 at 0 or $mdb at 0 ) and
        ( ( (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and
        ( (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        or (
        any of ( $php_write* ) or
        all of ( $php_multi_write* )
        )
        ) ) or
        ( (
            any of ( $cjsp* )
        )
        and (
        1 of ( $payload* ) or
        all of ( $rt_payload* )
        )
        ) or
        ( (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) ) )
}

rule WEBSHELL_Mixed_OBFUSC {
   meta:
      description = "Detects webshell with mixed obfuscation commands"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      date = "2023-01-28"
      modified = "2023-04-05"
      hash1 = "8c4e5c6bdfcc86fa27bdfb075a7c9a769423ec6d53b73c80cbc71a6f8dd5aace"
      hash2 = "78f2086b6308315f5f0795aeaa75544128f14889a794205f5fc97d7ca639335b"
      hash3 = "3bca764d44074820618e1c831449168f220121698a7c82e9909f8eab2e297cbd"
      hash4 = "b26b5e5cba45482f486ff7c75b54c90b7d1957fd8e272ddb4b2488ec65a2936e"
      hash5 = "e217be2c533bfddbbdb6dc6a628e0d8756a217c3ddc083894e07fd3a7408756c"
      score = 50
      id = "dcb4054b-0c87-5cd0-9297-7fd5f2e37437"
   strings:
      $s1 = "rawurldecode/*" ascii
      $s2 = "preg_replace/*" ascii
      $s3 = " __FILE__/*" ascii
      $s4 = "strlen/*" ascii
      $s5 = "str_repeat/*" ascii
      $s6 = "basename/*" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 4 of them ))
}

rule WEBSHELL_Cookie_Post_Obfuscation {
    meta:
        description = "Detects webshell using cookie POST"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2023-01-28"
        modified = "2023-04-05"
        license = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        hash = "d08a00e56feb78b7f6599bad6b9b1d8626ce9a6ea1dfdc038358f4c74e6f65c9"
        hash = "2ce5c4d31682a5a59b665905a6f698c280451117e4aa3aee11523472688edb31"
        hash = "ff732d91a93dfd1612aed24bbb4d13edb0ab224d874f622943aaeeed4356c662"
        hash = "a3b64e9e065602d2863fcab641c75f5d8ec67c8632db0f78ca33ded0f4cea257"
        hash = "d41abce305b0dc9bd3a9feb0b6b35e8e39db9e75efb055d0b1205a9f0c89128e"
        hash = "333560bdc876fb0186fae97a58c27dd68123be875d510f46098fc5a61615f124"
        hash = "2efdb79cdde9396ff3dd567db8876607577718db692adf641f595626ef64d3a4"
        hash = "e1bd3be0cf525a0d61bf8c18e3ffaf3330c1c27c861aede486fd0f1b6930f69a"
        hash = "f8cdedd21b2cc29497896ec5b6e5863cd67cc1a798d929fd32cdbb654a69168a"

        id = "cc5ded80-5e58-5b25-86d1-1c492042c740"
    strings:
        $s1 = "]($_COOKIE, $_POST) as $"
        $s2 = "function"
        $s3 = "Array"
    condition:
    ( uint16(0) == 0x3f3c and filesize < 100KB and ( all of them ))
}

rule webshell_php_by_string_obfuscation {
	meta:
		description = "PHP file containing obfuscation strings. Might be legitimate code obfuscated for whatever reasons, a webshell or can be used to insert malicious Javascript for credit card skimming"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
        score = 75
		date = "2021/01/09"
		hash = "e4a15637c90e8eabcbdc748366ae55996dbec926382220c423e754bd819d22bc"
	strings:
		$opbs13 = "{\"_P\"./*-/*-*/\"OS\"./*-/*-*/\"T\"}" wide ascii
		$opbs14 = "/*-/*-*/\"" wide ascii
		$opbs16 = "'ev'.'al'" wide ascii
		$opbs17 = "'e'.'val'" wide ascii
		$opbs18 = "e'.'v'.'a'.'l" wide ascii
		$opbs19 = "bas'.'e6'." wide ascii
		$opbs20 = "ba'.'se6'." wide ascii
		$opbs21 = "as'.'e'.'6'" wide ascii
		$opbs22 = "gz'.'inf'." wide ascii
		$opbs23 = "gz'.'un'.'c" wide ascii
		$opbs24 = "e'.'co'.'d" wide ascii
		$opbs25 = "cr\".\"eat" wide ascii
		$opbs26 = "un\".\"ct" wide ascii
		$opbs27 = "'c'.'h'.'r'" wide ascii
		$opbs28 = "\"ht\".\"tp\".\":/\"" wide ascii
		$opbs29 = "\"ht\".\"tp\".\"s:" wide ascii
		$opbs31 = "'ev'.'al'" nocase wide ascii
		$opbs32 = "eval/*" nocase wide ascii
		$opbs33 = "eval(/*" nocase wide ascii
		$opbs34 = "eval(\"/*" nocase wide ascii
		$opbs36 = "assert/*" nocase wide ascii
		$opbs37 = "assert(/*" nocase wide ascii
		$opbs38 = "assert(\"/*" nocase wide ascii
		$opbs40 = "'ass'.'ert'" nocase wide ascii
		$opbs41 = "${'_'.$_}['_'](${'_'.$_}['__'])" wide ascii
		$opbs44 = "'s'.'s'.'e'.'r'.'t'" nocase wide ascii
		$opbs45 = "'P'.'O'.'S'.'T'" wide ascii
		$opbs46 = "'G'.'E'.'T'" wide ascii
		$opbs47 = "'R'.'E'.'Q'.'U'" wide ascii
		$opbs48 = "se'.(32*2)" nocase
		$opbs49 = "'s'.'t'.'r_'" nocase
		$opbs50 = "'ro'.'t13'" nocase
		$opbs51 = "c'.'od'.'e" nocase
		$opbs53 = "e'. 128/2 .'_' .'d"
        // move malicious code out of sight if line wrapping not enabled
		$opbs54 = "<?php                                                                                                                                                                                " //here I end
		$opbs55 = "=chr(99).chr(104).chr(114);$_"
		$opbs56 = "\\x47LOBAL"
		$opbs57 = "pay\".\"load"
		$opbs58 = "bas'.'e64"
		$opbs59 = "dec'.'ode"
		$opbs60 = "fla'.'te"
        // rot13 of eval($_POST
		$opbs70 = "riny($_CBFG["
		$opbs71 = "riny($_TRG["
		$opbs72 = "riny($_ERDHRFG["
		$opbs73 = "eval(str_rot13("
		$opbs74 = "\"p\".\"r\".\"e\".\"g\""
		$opbs75 = "$_'.'GET"
		$opbs76 = "'ev'.'al("
        // eval( in hex
		$opbs77 = "\\x65\\x76\\x61\\x6c\\x28" wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

	condition:
		filesize < 500KB
		and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        ) and 
        any of ( $opbs* ) 
}

rule webshell_case_anomly {
	meta:
		description = "Casing anomly in typical webshell commands"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/05/11"
        reference = "Idea from https://github.com/Neo23x0/signature-base/blob/master/yara/gen_case_anomalies.yar"
        score = 70
	strings:
        $e = "eval" nocase fullword wide ascii
        $en1 = "eval" fullword wide ascii
        $en2 = "Eval" fullword wide ascii
        $en3 = "EVAL" fullword wide ascii
        $en4 = "$eVal" nocase fullword wide ascii
        $a = "assert" nocase fullword wide ascii
        $an1 = "assert" fullword wide ascii
        $an2 = "Assert" fullword wide ascii
        $an3 = "ASSERT" fullword wide ascii
        $c = "CreateObject" nocase fullword wide ascii
        $cn1 = "CreateObject" fullword wide ascii
        $cn2 = "createobject" fullword wide ascii
        $cn3 = "createObject" fullword wide ascii
        $cn4 = "Createobject" fullword wide ascii
        $cn5 = "CREATEOBJECT" fullword wide ascii
        $f = "CreateTextFile" nocase fullword wide ascii
        $fn1 = "CreateTextFile" fullword wide ascii
        $fn2 = "createtextfile" fullword wide ascii
        $fn3 = "createTextFile" fullword wide ascii
        $fn4 = "CreatetextFile" fullword wide ascii
        $fn5 = "CreateTextfile" fullword wide ascii
        $fn6 = "createtextFile" fullword wide ascii
        $fn7 = "Createtextfile" fullword wide ascii
        $fn8 = "CREATETEXTFILE" fullword wide ascii
        $s = "sqlclient" nocase fullword wide ascii
        $sn1 = "sqlclient" fullword wide ascii
        $sn2 = "SQLclient" fullword wide ascii
        $sn3 = "SQLClient" fullword wide ascii
        $sn4 = "sqlClient" fullword wide ascii
        $sn5 = "SqlClient" fullword wide ascii
        $sn6 = "SQLCLIENT" fullword wide ascii
        $t = "ExecuteStatement" nocase fullword wide ascii
        $tn1 = "ExecuteStatement" fullword wide ascii
        $tn2 = "executestatement" fullword wide ascii
        $tn3 = "Executestatement" fullword wide ascii
        $tn4 = "executeStatement" fullword wide ascii
        $tn5 = "EXECUTESTATEMENT" fullword wide ascii
        $q = "select" nocase fullword wide ascii
        $qn1 = "select" fullword wide ascii
        $qn2 = "Select" fullword wide ascii
        $qn3 = "SELECT" fullword wide ascii
        $x = "execute" nocase fullword wide ascii
        $xn1 = "execute" fullword wide ascii
        $xn2 = "Execute" fullword wide ascii
        $xn3 = "EXECUTE" fullword wide ascii
        $r = "request" nocase fullword wide ascii
        $rn1 = "request" fullword wide ascii
        $rn2 = "Request" fullword wide ascii
        $rn3 = "REQUEST" fullword wide ascii
        // common typo
        $rn4 = "REquest" fullword wide ascii

        // capa_php_old_safe
        $php_short = "<?" wide ascii
		// prevent xml and asp from hitting with the short tag
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 

		// of course the new tags should also match
        // already matched by "<?"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii

        // capa_asp
		$tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
		$tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
        // <% eval
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="
        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword

        // capa_jsp
		$cjsp1 = "<%" ascii wide
		$cjsp2 = "<jsp:" ascii wide
		$cjsp3 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp4 = "/jstl/core" ascii wide

	condition:
        (
            ( // capa_php_old_safe
                (
                    ( 
                        $php_short in (0..100) or 
                        $php_short in (filesize-1000..filesize)
                    )
                    and not any of ( $no_* )
                ) or any of ( $php_new* )
            ) or 
            ( // capa_asp
                (
                    any of ( $tagasp_long* ) or
                    // TODO: yara_push_private_rules.py doesn't do private rules in private rules yet
                    any of ( $tagasp_classid* ) or
                    (
                        $tagasp_short1 and
                        $tagasp_short2 in ( filesize-100..filesize ) 
                    ) or (
                        $tagasp_short2 and (
                            $tagasp_short1 in ( 0..1000 ) or
                            $tagasp_short1 in ( filesize-1000..filesize ) 
                        )
                    ) 
                ) and not ( 
                    (
                        any of ( $perl* ) or
                        $php1 at 0 or
                        $php2 at 0 
                    ) or (
                        ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                        )
                )
            ) or 
            ( // capa_jsp
                any of ( $cjsp* )
            )
        ) and
        (
            (
                filesize < 500KB and
                (
                    ( #a > ( #an1 + #an2 + #an3 ) ) or
                    ( #r > ( #rn1 + #rn2 + #rn3 + #rn4 ) ) or
                    ( #q > ( #qn1 + #qn2 + #qn3 ) ) or
                    ( #c > ( #cn1 + #cn2+ #cn3 + #cn4 + #cn5 ) ) or
                    ( #t > ( #tn1 + #tn2+ #tn3 + #tn4 + #tn5 ) ) or
                    ( #s > ( #sn1 + #sn2+ #sn3 + #sn4 + #sn5 + #sn6 ) ) or
                    ( #f > ( #fn1 + #fn2+ #fn3 + #fn4 + #fn5 + #fn6 +#fn7 + #fn8 ) ) or
                    ( #x > ( #xn1 + #xn2 + #xn3 ) )
                )
            ) or (
                // eval is a short string, look only in small files to avoid fp in binary garbage:
                filesize < 30KB and
                ( #e > ( #en1 + #en2 + #en3 + #en4 ) )
            )
        )
}

rule WEBSHELL_PHP_HEX_ENCODE
{
    meta:
        description = "PHP webshell contains encoded function names"
        score = 75
        author = "Arnim Rupp modified by OPSWAT"
        hash = "274fa74438e744681dc54bab192d7f71177d82bb75bbdba440bc50ce161cdcbf"
        hash = "b173125982ecde8e3b0faad8c381ed5cbb46a606afa505de64dbfa6a0c46a93c"
        hash = "ad9eefdc9c9109fe6d80aaa5e8f5232aead3ac9dc67a9578ed70c6426956a438"
    strings:
        
        $hex_gen1 = "7068705F756E616D65" nocase wide ascii // php_uname
        $hex_gen2 = "73657373696F6E5F7374617274" nocase wide ascii // session_start
        $hex_gen3 = "6572726F725F7265706F7274696E67" nocase wide ascii // error_reporting
        $hex_gen4 = "70687076657273696F6E" nocase wide ascii // phpversion
        $hex_gen5 = "6D696D655F636F6E74656E745F74797065" nocase wide ascii // mime_content_type
        $hex_gen6 = "737072696E7466" nocase wide ascii // sprintf
        $hex_gen7 = "666C617368" nocase wide ascii // flash
        $hex_gen8 = "74727565" nocase wide ascii // true
        $hex_gen9 = "64617465" nocase wide ascii // date
        $hex_gen10 = "676574686F737462796E616D65" nocase wide ascii // gethostbyname
        $hex_file1 = "66696C655F7075745F636F6E74656E7473" nocase wide ascii // file_put_contents
        $hex_file2 = "66696C655F6765745F636F6E74656E7473" nocase wide ascii // file_get_contents
        $hex_file3 = "66696C657065726D73" nocase wide ascii // fileperms
        $hex_file4 = "66696C656D74696D65" nocase wide ascii // filemtime
        $hex_file5 = "66696C6574797065" nocase wide ascii // filetype
        $hex_file6 = "6D6F76655F75706C6F616465645F66696C65" nocase wide ascii // move_uploaded_file
        $hex_file7 = "72656E616D65" nocase wide ascii // rename
        $hex_file8 = "7363616E646972" nocase wide ascii // scandir
        $hex_file9 = "6368646972" nocase wide ascii // chdir
        $hex_file10 = "676574637764" nocase wide ascii // getcwd
        $hex_file11 = "6469726E616D65" nocase wide ascii // dirname
        $hex_file12 = "6673697A65" nocase wide ascii // fsize
        $hex_file13 = "6D6B646972" nocase wide ascii // mkdir
        $hex_file14 = "726D646972" nocase wide ascii // rmdir
        $hex_file15 = "756E6C696E6B" nocase wide ascii // unlink
        $hex_exec1 = "7368656C6C5F65786563" nocase wide ascii // shell_exec
        $hex_exec2 = "66756E6374696F6E5F657869737473" nocase wide ascii // function_exists
        $hex_exec3 = "6576616C" nocase wide ascii // eval
        $hex_exec4 = "65786563" nocase wide ascii // exec
        $hex_exec5 = "73797374656D" nocase wide ascii // system
        $hex_string1 = "737562737472" nocase wide ascii // substr
        $hex_string2 = "7374725F7265706C616365" nocase wide ascii // str_replace
        $hex_string3 = "68746D6C7370656369616C6368617273" nocase wide ascii // htmlspecialchars
        $hex_string4 = "6578706C6F6465" nocase wide ascii // explode
        
        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            3 of ($hex_gen1, $hex_gen2, $hex_gen3, $hex_gen4, $hex_gen5, $hex_gen6, $hex_gen7, $hex_gen8, $hex_gen9, $hex_gen10) and
            ( 4 of ($hex_file1, $hex_file2, $hex_file3, $hex_file4, $hex_file5, $hex_file6, $hex_file7, $hex_file8, $hex_file9, $hex_file10, $hex_file11, $hex_file12, $hex_file13, $hex_file14, $hex_file15) or
            any of ($hex_exec1, $hex_exec2, $hex_exec3, $hex_exec4, $hex_exec5) or
            any of ($hex_string1, $hex_string2, $hex_string3, $hex_string4) )
        )
}

rule WEBSHELL_PHP_Generic_Closure_Invoke
{
    meta:
        description = "PHP webshell reconstruct of a callable function for execution on user input"
        author = "Arnim Rupp modified by OPSWAT"
        hash = "856beff7281e884c4c6e6ee98edbfd4c2e76f9372c8426f30f1681e0553f85ee"
        score = 75
    strings:
        // Closure::fromCallable("system")->__invoke($_REQUEST[2]);
        $closure_invoke = /Closure::fromCallable\((["'][^"']+["']|\$[A-Za-z_][A-Za-z0-9_]*)\)\s*->\s*__invoke\(\s*{?\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            $closure_invoke
        ) and filesize < 400
}

rule WEBSHELL_PHP_OBFUSC_CUSTOM
{
    meta:
        description = "PHP webshell obfuscated custom with new findings"
        author = "Arnim Rupp modified by OPSWAT"
        hash1 = "c0bf94d232c43c8b0727748110e07d59f70464b1553343262c1b194c09400831"
        hash2 = "b8de0c915467be90f278943ab1e7560e3436bc44e953170fbb9b528b40e0d0e1"
        score = 75
    strings:
        // $k= 'sh';
        // $k.='el';
        // $k.='l_e';
        // $k.='xe';
        // $k.='c';
        $obf1 = /\$[A-Za-z_]\w*\s*=\s*['"][A-Za-z0-9_]+['"];\s*(\$[A-Za-z_]\w*\s*\.=\s*['"][A-Za-z0-9_]+['"];\s*)+/ wide ascii

        // "GLOBAL obfuscation" with many many append strings from a GLOBAL characters array. Ex:
        // $GLOBALS['a1f44'] = "\x35\x27\x9\x59\x7a\x55..."
        // $GLOBALS[$GLOBALS['a1f44'][46].$GLOBALS['a1f44'][0].$GLOBALS['a1f44'][53].$GLOBALS['a1f44'][9]] = $GLOBALS['a1f44'][53].$GLOBALS['a1f44'][81]
        $obf2 = ".$GLOBALS"

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            (#obf1 > 2) or (#obf2 > 200)
        )
}

rule WEBSHELL_PHP_Magic_Method
{
    meta:
        description = "PHP webshell ultilize magic method"
        author = "Arnim Rupp modified by OPSWAT"
        hash = "fe07af4384f079a92fcc6fafad3821823b17c941b18523fc59ab53d55db3a4ec"
        score = 50
    strings:
        $magic_method1 = "__construct" wide ascii
        $magic_method2 = "__destruct" wide ascii
        $magic_method3 = "__wakeup" wide ascii
        $magic_method4 = "__call" wide ascii
        $magic_method5 = "__callStatic" wide ascii
        $magic_method6 = "__sleep" wide ascii
        $magic_method7 = "__invoke" wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        $inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii
        $inp20 = "TSOP_" wide ascii
        $inp21 = /array\(\'(_POST|_GET|_REQUEST)\'\)/ wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
        $cpayload23 = /\bReflectionClass[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii

    condition:
        not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and (
            any of ( $magic_method* )
        )
}

rule WEBSHELL_PHP_Permission_Modification_Generic
{
    meta:
        description = "PHP webshell has capability of change file permissions"
        author = "Arnim Rupp modified by OPSWAT"
        hash1 = "fe07af4384f079a92fcc6fafad3821823b17c941b18523fc59ab53d55db3a4ec"
        score = 75
    strings:

        $perm1 = "chmod($_" wide ascii
        $perm2 = "chown($_" wide ascii
        $perm3 = "chgrp($_" wide ascii
        $perm4 = "umask($_" wide ascii
        $perm5= "fileperms($_" wide ascii
        
        // Action go with permission modification
        $action1 = "unlink($_" wide ascii
        $action2 = "symlink($_" wide ascii
        $action3 = "link($_" wide ascii
        $action4 = "readlink($_" wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        $inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii
        $inp20 = "TSOP_" wide ascii
        $inp21 = /file_get_contents\(\$/ wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii

    condition:
        not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and (
            (any of ( $perm* )) and (any of ($action*))
        )
}

rule WEBSHELL_PHP_DEC_ENCODE_GENERIC
{
    // Many webshell are encoded in decimal blob, that can be loaded by another loader
    meta:
        description = "PHP webshell are encoded in decimal blob, that can be loaded by another loader"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp modified by OPSWAT"
        score = 75
    strings:
        //strings from private rule capa_php_old_safe to confirm PHP shell in decimal encoded
        $php_short1 = "60 63"
        $php_short2 = "60, 63"
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "60 63 120 109 108 32 118 101 114 115 105 111 110"
        $no_xml2 = "60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110"
        $no_xml3 = "60 63 120 109 108 45 115 116 121 108 101 115 104 101 101 116"
        $no_xml4 = "60, 63, 120, 109, 108, 45, 15, 116, 121, 108, 101, 115, 104, 101, 101, 116"

        $no_asp1 = "60 37 64 76 65 78 71 85 65 71 69"
        $no_asp2 = "60, 37, 64, 76, 65, 78, 71, 85, 65, 71, 69"

        $no_asp3 = "60 115 99 114 105 112 116 32 108 97 110 103 117 97 103 101 61 34 40 118 98 41"
        $no_asp4 = "60, 115, 99, 114, 105, 112, 116, 32, 108, 97, 110, 103, 117, 97, 103, 101, 61, 34, 40, 118, 98, 41"
        $no_asp5 = "60 115 99 114 105 112 116 32 108 97 110 103 117 97 103 101 61 34 40 106 115 99 114 105 112 116 41"
        $no_asp6 = "60, 115, 99, 114, 105, 112, 116, 32, 108, 97, 110, 103, 117, 97, 103, 101, 61, 34, 40, 106, 115, 99, 114, 105, 112, 116, 41"
        $no_asp7 = "60 115 99 114 105 112 116 32 108 97 110 103 117 97 103 101 61 34 40 99 35 41"
        $no_asp8 = "60, 115, 99, 114, 105, 112, 116, 32, 108, 97, 110, 103, 117, 97, 103, 101, 61, 34, 40, 99, 35, 41"

        $no_pdf1 = "60 63 120 112 97 99 107 101 116"
        $no_pdf2 = "60, 63, 120, 112, 97, 99, 107, 101, 116"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = "60 63 112 104 112"
        $php_new2 = "60, 63, 112, 104, 112"
        $php_new3 = "60 115 99 114 105 112 116 32 108 97 110 103 117 97 103 101 61 92 34 112 104 112"
        $php_new4 = "60, 115, 99, 114, 105, 112, 116, 32, 108, 97, 110, 103, 117, 97, 103, 101, 61, 92, 34, 112, 104, 112"

        //strings from private rule capa_php_input modified minimal version
        $inp1 = "112 104 112 58 47 47 105 110 112 117 116"
        $inp2 = "112, 104, 112, 58, 47, 47, 105, 110, 112, 117, 116"
        $inp3 = "36 95 71 69 84 91"
        $inp4 = "36, 95, 71, 69, 84, 91"
        $inp5 = "36 95 80 79 83 84 91"
        $inp6 = "36, 95, 80, 79, 83, 84, 91"
        $inp7 = "36 95 82 69 81 85 69 83 84 91"
        $inp8 = "36, 95, 82, 69, 81, 85, 69, 83, 84, 91"
        $inp9 = "95 83 69 82 86 69 82 91 39 72 84 84 80 95"
        $inp10 = "95, 83, 69, 82, 86, 69, 82, 91, 39, 72, 84, 84, 80, 95"
        $inp11 = "95 83 69 82 86 69 82 91 34 72 84 84 80 95"
        $inp12 = "95, 83, 69, 82, 86, 69, 82, 91, 34, 72, 84, 84, 80, 95"
        $inp13 = "97 114 114 97 121 95 118 97 108 117 101 115 40 36 95 83 69 82 86 69 82 41"
        $inp14 = "97, 114, 114, 97, 121, 95, 118, 97, 108, 117, 101, 115, 40, 36, 95, 83, 69, 82, 86, 69, 82, 41"
        $inp15 = "103 101 116 101 110 118 40"
        $inp16 = "103, 101, 116, 101, 110, 118, 40"
        $inp17 = "102 105 108 101 95 103 101 116 95 99 111 110 116 101 110 116 115 40"
        $inp18 = "102, 105, 108, 101, 95, 103, 101, 116, 95, 99, 111, 110, 116, 101, 110, 116, 115, 40"
        $inp19 = "102 115 111 99 107 111 112 101 110 40"
        $inp20 = "102, 115, 111, 99, 107, 111, 112, 101, 110, 40"
        $inp21 = "103 122 105 110 102 108 97 116 101 40 98 97 115 101 54 52 95 100 101 99 111 100 101 40"
        $inp22 = "103, 122, 105, 110, 102, 108, 97, 116, 101, 40, 98, 97, 115, 101, 54, 52, 95, 100, 101, 99, 111, 100, 101, 40"

        //strings from private rule capa_php_payload minimal version of execution method
        $cpayload1 = "101 118 97 108 40"
        $cpayload2 = "101, 118, 97, 108, 40"
        $cpayload3 = "101 120 101 99 40"
        $cpayload4 = "101, 120, 101, 99, 40"
        $cpayload5 = "115 104 101 108 108 95 101 120 101 99 40"
        $cpayload6 = "115, 104, 101, 108, 108, 95, 101, 120, 101, 99, 40"
        $cpayload7 = "112 97 115 115 116 104 114 117 40"
        $cpayload8 = "112, 97, 115, 115, 116, 104, 114, 117, 40"
        $cpayload9 = "115 121 115 116 101 109 40"
        $cpayload10 = "115, 121, 115, 116, 101, 109, 40"
        $cpayload11 = "112 111 112 101 110 40"
        $cpayload12 = "112, 111, 112, 101, 110, 40"
        $cpayload13 = "112 114 111 99 95 111 112 101 110 40"
        $cpayload14 = "112, 114, 111, 99, 95, 111, 112, 101, 110, 40"
        $cpayload15 = "112 99 110 116 108 95 101 120 101 99 40"
        $cpayload16 = "112, 99, 110, 116, 108, 95, 101, 120, 101, 99, 40"
        $cpayload17 = "97 115 115 101 114 116 40"
        $cpayload18 = "97, 115, 115, 101, 114, 116, 40"
        $cpayload19 = "112 114 101 103 95 114 101 112 108 97 99 101 40"
        $cpayload20 = "112, 114, 101, 103, 95, 114, 101, 112, 108, 97, 99, 101, 40"
        $cpayload21 = "109 98 95 101 114 101 103 95 114 101 112 108 97 99 101 40"
        $cpayload22 = "109, 98, 95, 101, 114, 101, 103, 95, 114, 101, 112, 108, 97, 99, 101, 40"
        $cpayload23 = "109 98 95 101 114 101 103 105 95 114 101 112 108 97 99 101 40"
        $cpayload24 = "109, 98, 95, 101, 114, 101, 103, 105, 95, 114, 101, 112, 108, 97, 99, 101, 40"
        $cpayload25 = "99 114 101 97 116 101 95 102 117 110 99 116 105 111 110 40"
        $cpayload26 = "99, 114, 101, 97, 116, 101, 95, 102, 117, 110, 99, 116, 105, 111, 110, 40"
        $cpayload27 = "82 101 102 108 101 99 116 105 111 110 70 117 110 99 116 105 111 110 40"
        $cpayload28 = "82, 101, 102, 108, 101, 99, 116, 105, 111, 110, 70, 117, 110, 99, 116, 105, 111, 110, 40"
        $cpayload29 = "102 101 116 99 104 97 108 108 40 80 68 79 58 58 70 69 84 67 72 95 70 85 78 67"
        $cpayload30 = "102, 101, 116, 99, 104, 97, 108, 108, 40, 80, 68, 79, 58, 58, 70, 69, 84, 67, 72, 95, 70, 85, 78, 67"
        $cpayload31 = "109 111 118 101 95 117 112 108 111 97 100 101 100 95 102 105 108 101 40"
        $cpayload32 = "109, 111, 118, 101, 95, 117, 112, 108, 111, 97, 100, 101, 100, 95, 102, 105, 108, 101, 40"
        $cpayload33 = "112 114 111 99 95 111 112 101 110 40"
        $cpayload34 = "112, 114, 111, 99, 95, 111, 112, 101, 110, 40"
        $cpayload35 = "102 114 101 97 100 40"
        $cpayload36 = "102, 114, 101, 97, 100, 40"
        $cpayload37 = "102 119 114 105 116 101 40"
        $cpayload38 = "102, 119, 114, 105, 116, 101, 40"

        $m_cpayload_preg_filter1_1 = "112 114 101 103 95 102 105 108 116 101 114 40"
        $m_cpayload_preg_filter1_2 = "112, 114, 101, 103, 95, 102, 105, 108, 116, 101, 114, 40"
        $m_cpayload_preg_filter2_1 = "39 124 46 42 124 101 39"
        $m_cpayload_preg_filter2_2 = "39, 124, 46, 42, 124, 101, 39"

    condition:
        //any of them or
        (
            (
                (
                        $php_short1 in (0..100) or
                        $php_short1 in (filesize-1000..filesize) or
                        $php_short2 in (0..100) or
                        $php_short2 in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
            any of ( $cpayload* ) or
            ((any of ($m_cpayload_preg_filter1*)) and (any of ($m_cpayload_preg_filter2*)))
        )
}

// ===== Source: fsYara-original/executable/scriptLang/WShell_THOR_Webshells.yar =====

/*

   THOR APT Scanner - Web Shells Extract
   This rulset is a subset of all hack tool rules included in our
   APT Scanner THOR - the full featured APT scanner

   We will frequently update this file with new rules rated TLP:WHITE

   Florian Roth
   BSK Consulting GmbH
   Web: bsk-consulting.de

   revision: 20150122

*/
rule Weevely_Webshell : webshell
{
	meta:
		description = "Weevely Webshell - Generic Rule - heavily scrambled tiny web shell"
		author = "Florian Roth"
		reference = "http://www.ehacking.net/2014/12/weevely-php-stealth-web-backdoor-kali.html"
		date = "2014/12/14"
		score = 60

	strings:
		$php = {3C 3F 70 68 70}
		$s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
		$s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
		$s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
		$s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii

	condition:
		$php at 0 and all of ($s*) and filesize >570 and filesize <800
}

rule webshell_h4ntu_shell_powered_by_tsoi_ : webshell
{
	meta:
		description = "Web Shell - file h4ntu shell [powered by tsoi].php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "06ed0b2398f8096f1bebf092d0526137"

	strings:
		$s0 = {20 20 3C 54 44 3E 3C 44 49 56 20 53 54 59 4C 45 3D 5C 22 66 6F 6E 74 2D 66 61 6D 69 6C 79 3A 20 76 65 72 64 61 6E 61 3B 20 66 6F 6E 74 2D 73 69 7A 65 3A 20 31 30 70 78 3B 5C 22 3E 3C 62 3E 53 65 72 76 65 72 20 41 64 72 65 73 73 3A 3C 2F 62}
		$s3 = {20 20 3C 54 44 3E 3C 44 49 56 20 53 54 59 4C 45 3D 5C 22 66 6F 6E 74 2D 66 61 6D 69 6C 79 3A 20 76 65 72 64 61 6E 61 3B 20 66 6F 6E 74 2D 73 69 7A 65 3A 20 31 30 70 78 3B 5C 22 3E 3C 62 3E 55 73 65 72 20 49 6E 66 6F 3A 3C 2F 62 3E 20 75 69}
		$s4 = {20 20 20 20 3C 54 44 3E 3C 44 49 56 20 53 54 59 4C 45 3D 5C 22 66 6F 6E 74 2D 66 61 6D 69 6C 79 3A 20 76 65 72 64 61 6E 61 3B 20 66 6F 6E 74 2D 73 69 7A 65 3A 20 31 30 70 78 3B 5C 22 3E 3C 3F 3D 20 24 69 6E 66 6F 20 3F 3E 3A 20 3C 3F 3D 20}
		$s5 = {3C 49 4E 50 55 54 20 54 59 50 45 3D 5C 22 74 65 78 74 5C 22 20 4E 41 4D 45 3D 5C 22 63 6D 64 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 73 74 72 69 70 73 6C 61 73 68 65 73 28 68 74 6D 6C 65 6E 74 69 74 69 65 73 28 24}

	condition:
		all of them
}

rule webshell_PHP_sql : webshell
{
	meta:
		description = "Web Shell - file sql.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2cf20a207695bbc2311a998d1d795c35"

	strings:
		$s0 = {24 72 65 73 75 6C 74 3D 6D 79 73 71 6C 5F 6C 69 73 74 5F 74 61 62 6C 65 73 28 24 64 62 29 20 6F 72 20 64 69 65 20 28 5C 22 24 68 5F 65 72 72 6F 72 3C 62 3E 5C 22 2E 6D 79 73 71 6C 5F 65 72 72 6F 72 28 29 2E 5C 22 3C 2F 62 3E 24 66 5F}
		$s4 = {70 72 69 6E 74 20 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 24 5F 53 45 52 56 45 52 5B 50 48 50 5F 53 45 4C 46 5D 3F 73 3D 24 73 26 6C 6F 67 69 6E 3D 24 6C 6F 67 69 6E 26 70 61 73 73 77 64 3D 24 70 61 73 73 77 64 26}

	condition:
		all of them
}

rule webshell_PHP_a : webshell
{
	meta:
		description = "Web Shell - file a.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e3b461f7464d81f5022419d87315a90d"

	strings:
		$s1 = {65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 5C 22 2E 20 73 74 72 72 65 76 28 73 75 62 73 74 72 28 73 74 72 73 74 72 28 73 74 72 72 65 76 28 24 77 6F 72 6B 5F 64 69 72 29 2C 20 5C 22 2F 5C 22}
		$s2 = {65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 24 77 6F 72 6B 5F 64 69 72 5C 5C 5C 22 20 73 65 6C 65 63 74 65 64 3E 43 75 72 72 65 6E 74 20 44 69 72 65 63 74 6F 72 79 3C 2F 6F 70 74 69 6F 6E 3E}
		$s4 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 73 75 62 6D 69 74 5F 62 74 6E 5C 22 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 45 78 65 63 75 74 65 20 43 6F 6D 6D 61 6E 64 5C 22 3E 3C 2F 70 3E 20}

	condition:
		2 of them
}

rule webshell_iMHaPFtp_2 : webshell
{
	meta:
		description = "Web Shell - file iMHaPFtp.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "12911b73bc6a5d313b494102abcf5c57"

	strings:
		$s8 = {69 66 20 28 24 6C 29 20 65 63 68 6F 20 27 3C 61 20 68 72 65 66 3D 5C 22 27 20 2E 20 24 73 65 6C 66 20 2E 20 27 3F 61 63 74 69 6F 6E 3D 70 65 72 6D 69 73 73 69 6F 6E 26 61 6D 70 3B 66 69 6C 65 3D 27 20 2E 20 75 72 6C 65 6E 63 6F 64 65 28 24}
		$s9 = {72 65 74 75 72 6E 20 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27 52 30 6C 47 4F 44 6C 68 45 51 41 4E 41 4A 45 44 41 4D 77 41 41 50 2F 2F 2F 35 6D 5A 6D 66 2F 2F 2F 79 48 35 42 41 48 6F 41 77 4D 41 4C 41 41 41 41 41 41 52 41 41 30 41 41 41}

	condition:
		1 of them
}

rule webshell_Jspspyweb : webshell
{
	meta:
		description = "Web Shell - file Jspspyweb.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "4e9be07e95fff820a9299f3fb4ace059"

	strings:
		$s0 = {20 20 20 20 20 20 6F 75 74 2E 70 72 69 6E 74 28 5C 22 3C 74 72 3E 3C 74 64 20 77 69 64 74 68 3D 27 36 30 25 27 3E 5C 22 2B 73 74 72 43 75 74 28 63 6F 6E 76 65 72 74 50 61 74 68 28 6C 69 73 74 5B 69 5D 2E 67 65 74 50 61 74 68 28 29 29 2C 37}
		$s3 = {20 20 5C 22 72 65 67 20 61 64 64 20 5C 5C 5C 22 48 4B 45 59 5F 4C 4F 43 41 4C 5F 4D 41 43 48 49 4E 45 5C 5C 5C 5C 53 59 53 54 45 4D 5C 5C 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 5C 5C 43 6F 6E 74 72 6F 6C}

	condition:
		all of them
}

rule webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2 : webshell
{
	meta:
		description = "Web Shell - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "49ad9117c96419c35987aaa7e2230f63"

	strings:
		$s0 = {64 69 65 28 5C 22 5C 5C 6E 57 65 6C 63 6F 6D 65 2E 2E 20 42 79 20 54 68 69 73 20 73 63 72 69 70 74 20 79 6F 75 20 63 61 6E 20 6A 75 6D 70 20 69 6E 20 74 68 65 20 28 53 61 66 65 20 4D 6F 64 65 3D 4F 4E 29 20 2E 2E 20 45 6E 6A 6F 79 5C 5C 6E}
		$s1 = {4D 6F 64 65 20 53 68 65 6C 6C 20 76 31 2E 30 3C 2F 66 6F 6E 74 3E 3C 2F 73 70 61 6E 3E 3C 2F 61 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 22 57 65 62 64 69 6E 67 73 5C 22 20 73 69 7A 65 3D 5C 22 36 5C 22 20 63 6F 6C 6F 72}

	condition:
		1 of them
}

rule webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend : webshell
{
	meta:
		description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "089ff24d978aeff2b4b2869f0c7d38a3"

	strings:
		$s2 = {65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 27 3F 69 64 3D 66 6D 26 66 63 68 6D 6F 64 3D 24 64 69 72 24 66 69 6C 65 27 3E 3C 73 70 61 6E 20 73 74 79 6C 65 3D 27 74 65 78 74 2D 64 65 63 6F 72 61 74 69 6F 6E 3A 20 6E 6F 6E 65 27 3E 3C 66 6F}
		$s3 = {66 70 75 74 73 20 28 24 66 70 20 2C 5C 22 5C 5C 6E 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 5C 5C 6E 57 65 6C 63 6F 6D 65 20 54 30 20 53 69 6D}

	condition:
		1 of them
}

rule webshell_phpshell_2_1_pwhash : webshell
{
	meta:
		description = "Web Shell - file pwhash.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ba120abac165a5a30044428fac1970d8"

	strings:
		$s1 = {3C 74 74 3E 26 6E 62 73 70 3B 3C 2F 74 74 3E 5C 22 20 28 73 70 61 63 65 29 2C 20 5C 22 3C 74 74 3E 5B 3C 2F 74 74 3E 5C 22 20 28 6C 65 66 74 20 62 72 61 63 6B 65 74 29 2C 20 5C 22 3C 74 74 3E 7C 3C 2F 74 74 3E 5C 22 20 28 70 69}
		$s3 = {77 6F 72 64 3A 20 5C 22 3C 74 74 3E 6E 75 6C 6C 3C 2F 74 74 3E 5C 22 2C 20 5C 22 3C 74 74 3E 79 65 73 3C 2F 74 74 3E 5C 22 2C 20 5C 22 3C 74 74 3E 6E 6F 3C 2F 74 74 3E 5C 22 2C 20 5C 22 3C 74 74 3E 74 72 75 65 3C 2F 74 74 3E 5C 22 2C}

	condition:
		1 of them
}

rule webshell_PHPRemoteView : webshell
{
	meta:
		description = "Web Shell - file PHPRemoteView.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "29420106d9a81553ef0d1ca72b9934d9"

	strings:
		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 73 75 62 6D 69 74 20 76 61 6C 75 65 3D 27 5C 22 2E 6D 6D 28 5C 22 44 65 6C 65 74 65 20 61 6C 6C 20 64 69 72 2F 66 69 6C 65 73 20 72 65 63 75 72 73 69 76 65 5C 22 29 2E 5C 22 20 28 72 6D 20 2D 66 72 29 27}
		$s4 = {3C 61 20 68 72 65 66 3D 27 24 73 65 6C 66 3F 63 3D 64 65 6C 65 74 65 26 63 32 3D 24 63 32 26 63 6F 6E 66 69 72 6D 3D 64 65 6C 65 74 65 26 64 3D 5C 22 2E 75 72 6C 65 6E 63 6F 64 65 28 24 64 29 2E 5C 22 26 66 3D 5C 22 2E 75}

	condition:
		1 of them
}

rule webshell_jsp_12302 : webshell
{
	meta:
		description = "Web Shell - file 12302.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a3930518ea57d899457a62f372205f7f"

	strings:
		$s0 = {3C 2F 66 6F 6E 74 3E 3C 25 6F 75 74 2E 70 72 69 6E 74 28 72 65 71 75 65 73 74 2E 67 65 74 52 65 61 6C 50 61 74 68 28 72 65 71 75 65 73 74 2E 67 65 74 53 65 72 76 6C 65 74 50 61 74 68 28 29 29 29 3B 20 25 3E}
		$s1 = {3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 69 6F 2E 2A 2C 6A 61 76 61 2E 75 74 69 6C 2E 2A 2C 6A 61 76 61 2E 6E 65 74 2E 2A 5C 22 25 3E}
		$s4 = {53 74 72 69 6E 67 20 70 61 74 68 3D 6E 65 77 20 53 74 72 69 6E 67 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 74 68 5C 22 29 2E 67 65 74 42 79 74 65 73 28 5C 22 49 53 4F 2D 38 38 35 39 2D 31 5C 22}

	condition:
		all of them
}

rule webshell_caidao_shell_guo : webshell
{
	meta:
		description = "Web Shell - file guo.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9e69a8f499c660ee0b4796af14dc08f0"

	strings:
		$s0 = {3C 3F 70 68 70 20 28 24 77 77 77 3D 20 24 5F 50 4F 53 54 5B 27 69 63 65 27 5D 29 21}
		$s1 = {40 70 72 65 67 5F 72 65 70 6C 61 63 65 28 27 2F 61 64 2F 65 27 2C 27 40 27 2E 73 74 72 5F 72 6F 74 31 33 28 27 72 69 6E 79 27 29 2E 27 28 24 77 77}

	condition:
		1 of them
}

rule webshell_PHP_redcod : webshell
{
	meta:
		description = "Web Shell - file redcod.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5c1c8120d82f46ff9d813fbe3354bac5"

	strings:
		$s0 = {48 38 70 30 62 47 46 4F 45 79 37 65 41 6C 79 34 68 34 45 34 6F 38 38 4C 54 53 56 48 6F 41 67 6C 4A 32 4B 4C 51 68 55 77}
		$s1 = {48 4B 50 37 64 56 79 43 66 38 63 67 6E 57 46 79 38 6F 63 6A 72 50 35 66 66 7A 6B 6E 39 4F 44 72 6F 4D 30 2F 72 61 48 6D}

	condition:
		all of them
}

rule webshell_remview_fix : webshell
{
	meta:
		description = "Web Shell - file remview_fix.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a24b7c492f5f00e2a19b0fa2eb9c3697"

	strings:
		$s4 = {3C 61 20 68 72 65 66 3D 27 24 73 65 6C 66 3F 63 3D 64 65 6C 65 74 65 26 63 32 3D 24 63 32 26 63 6F 6E 66 69 72 6D 3D 64 65 6C 65 74 65 26 64 3D 5C 22 2E 75 72 6C 65 6E 63 6F 64 65 28 24 64 29 2E 5C 22 26 66 3D 5C 22 2E 75}
		$s5 = {65 63 68 6F 20 5C 22 3C 50 3E 3C 68 72 20 73 69 7A 65 3D 31 20 6E 6F 73 68 61 64 65 3E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E}

	condition:
		1 of them
}

rule webshell_asp_cmd : webshell
{
	meta:
		description = "Web Shell - file cmd.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "895ca846858c315a3ff8daa7c55b3119"

	strings:
		$s0 = {3C 25 3D 20 5C 22 5C 5C 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 55 73 65 72 4E 61 6D 65 20 25 3E}
		$s1 = {53 65 74 20 6F 46 69 6C 65 53 79 73 20 3D 20 53 65 72 76 65 72 2E 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 53 63 72 69 70 74 69 6E 67 2E 46 69 6C 65 53 79 73 74 65 6D 4F 62 6A 65 63 74 5C 22 29}
		$s3 = {43 61 6C 6C 20 6F 53 63 72 69 70 74 2E 52 75 6E 20 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 65 6D 70 46 69 6C 65 2C 20 30 2C 20 54 72 75 65 29}

	condition:
		1 of them
}

rule webshell_php_sh_server : webshell
{
	meta:
		description = "Web Shell - file server.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 50
		hash = "d87b019e74064aa90e2bb143e5e16cfa"

	strings:
		$s0 = {65 76 61 6C 28 67 65 74 65 6E 76 28 27 48 54 54 50 5F 43 4F 44 45 27 29 29 3B}

	condition:
		all of them
}

rule webshell_PH_Vayv_PH_Vayv : webshell
{
	meta:
		description = "Web Shell - file PH Vayv.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "35fb37f3c806718545d97c6559abd262"

	strings:
		$s0 = {73 74 79 6C 65 3D 5C 22 42 41 43 4B 47 52 4F 55 4E 44 2D 43 4F 4C 4F 52 3A 20 23 65 61 65 39 65 39 3B 20 42 4F 52 44 45 52 2D 42 4F 54 54 4F 4D 3A 20 23 30 30 30 30 30 30 20 31 70 78 20 69 6E}
		$s4 = {3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 38 35 38 35 38 35 5C 22 3E 53 48 4F 50 45 4E 3C 2F 66 6F 6E 74 3E 3C 2F 61 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 22 56 65 72 64 61 6E 61 5C 22 20 73 74 79 6C 65}

	condition:
		1 of them
}

rule webshell_caidao_shell_ice : webshell
{
	meta:
		description = "Web Shell - file ice.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "6560b436d3d3bb75e2ef3f032151d139"

	strings:
		$s0 = {3C 25 65 76 61 6C 20 72 65 71 75 65 73 74 28 5C 22 69 63 65 5C 22 29 25 3E}

	condition:
		all of them
}

rule webshell_cihshell_fix : webshell
{
	meta:
		description = "Web Shell - file cihshell_fix.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3823ac218032549b86ee7c26f10c4cb5"

	strings:
		$s7 = {3C 74 72 20 73 74 79 6C 65 3D 27 62 61 63 6B 67 72 6F 75 6E 64 3A 23 32 34 32 34 32 34 3B 27 20 3E 3C 74 64 20 73 74 79 6C 65 3D 27 70 61 64 64 69 6E 67 3A 31 30 70 78 3B 27 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 27 27 20 65 6E 63 74 79}
		$s8 = {69 66 20 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 6D 79 73 71 6C 77 5F 68 6F 73 74 27 5D 29 29 7B 24 64 62 68 6F 73 74 20 3D 20 24 5F 50 4F 53 54 5B 27 6D 79 73 71 6C 77 5F 68 6F 73 74 27 5D 3B 7D 20 65 6C 73 65 20 7B 24 64 62 68 6F 73}

	condition:
		1 of them
}

rule webshell_asp_shell : webshell
{
	meta:
		description = "Web Shell - file shell.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e63f5a96570e1faf4c7b8ca6df750237"

	strings:
		$s7 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 6E 61 6D 65 3D 5C 22 53 65 6E 64 5C 22 20 76 61 6C 75 65 3D 5C 22 47 4F 21 5C 22 3E}
		$s8 = {3C 54 45 58 54 41 52 45 41 20 4E 41 4D 45 3D 5C 22 31 39 38 38 5C 22 20 52 4F 57 53 3D 5C 22 31 38 5C 22 20 43 4F 4C 53 3D 5C 22 37 38 5C 22 3E 3C 2F 54 45 58 54 41 52 45 41 3E}

	condition:
		all of them
}

rule webshell_Private_i3lue : webshell
{
	meta:
		description = "Web Shell - file Private-i3lue.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "13f5c7a035ecce5f9f380967cf9d4e92"

	strings:
		$s8 = {63 61 73 65 20 31 35 3A 20 24 69 6D 61 67 65 20 2E 3D 20 5C 22 5C 5C 32 31 5C 5C 30 5C 5C}

	condition:
		all of them
}

rule webshell_php_up : webshell
{
	meta:
		description = "Web Shell - file up.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "7edefb8bd0876c41906f4b39b52cd0ef"

	strings:
		$s0 = {63 6F 70 79 28 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 27 75 73 65 72 66 69 6C 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 20 24 5F 50 4F 53 54 5B 27 72 65 6D 6F 74 65 66 69 6C 65 27 5D 29 3B}
		$s3 = {69 66 28 69 73 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 27 75 73 65 72 66 69 6C 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 29 29 20 7B}
		$s8 = {65 63 68 6F 20 5C 22 55 70 6C 6F 61 64 65 64 20 66 69 6C 65 3A 20 5C 22 20 2E 20 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 27 75 73 65 72 66 69 6C 65 27 5D 5B 27 6E 61 6D 65 27 5D 3B}

	condition:
		2 of them
}

rule webshell_Mysql_interface_v1_0
{
	meta:
		description = "Web Shell - file Mysql interface v1.0.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a12fc0a3d31e2f89727b9678148cd487"

	strings:
		$s0 = {65 63 68 6F 20 5C 22 3C 74 64 3E 3C 61 20 68 72 65 66 3D 27 24 50 48 50 5F 53 45 4C 46 3F 61 63 74 69 6F 6E 3D 64 72 6F 70 44 42 26 64 62 6E 61 6D 65 3D 24 64 62 6E 61 6D 65 27 20 6F 6E 43 6C 69 63 6B 3D 5C 5C 5C 22 72 65 74 75 72 6E}

	condition:
		all of them
}

rule webshell_php_s_u
{
	meta:
		description = "Web Shell - file s-u.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "efc7ba1a4023bcf40f5e912f1dd85b5a"

	strings:
		$s6 = {3C 61 20 68 72 65 66 3D 5C 22 3F 61 63 74 3D 64 6F 5C 22 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 72 65 64 5C 22 3E 47 6F 20 45 78 65 63 75 74 65 3C 2F 66 6F 6E 74 3E 3C 2F 61 3E 3C 2F 62 3E 3C 62 72 20 2F 3E 3C 74 65 78 74 61 72 65 61}

	condition:
		all of them
}

rule webshell_phpshell_2_1_config
{
	meta:
		description = "Web Shell - file config.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "bd83144a649c5cc21ac41b505a36a8f3"

	strings:
		$s1 = {3B 20 28 63 68 6F 6F 73 65 20 67 6F 6F 64 20 70 61 73 73 77 6F 72 64 73 21 29 2E 20 20 41 64 64 20 75 73 65 73 20 61 73 20 73 69 6D 70 6C 65 20 27 75 73 65 72 6E 61 6D 65 20 3D 20 5C 22 70 61 73 73 77 6F 72 64 5C 22 27 20 6C 69 6E 65 73 2E}

	condition:
		all of them
}

rule webshell_asp_EFSO_2
{
	meta:
		description = "Web Shell - file EFSO_2.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a341270f9ebd01320a7490c12cb2e64c"

	strings:
		$s0 = {25 38 40 23 40 26 50 7E 2C 50 2C 50 50 2C 4D 56 7E 34 42 50 5E 7E 2C 4E 53 7E 6D 7E 50 58 63 33 2C 5F 50 57 62 53 50 55 20 57 7E 7E 5B 75 33 46 66 66 73 7E 2F 25 40 23 40 26 7E 7E 2C 50 50 7E 7E 2C 4D 21 50 6D 53 2C 34 53 2C 6D 42 50 4E 42}

	condition:
		all of them
}

rule webshell_jsp_up
{
	meta:
		description = "Web Shell - file up.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "515a5dd86fe48f673b72422cccf5a585"

	strings:
		$s9 = {2F 2F 20 42 55 47 3A 20 43 6F 72 74 61 20 65 6C 20 66 69 63 68 65 72 6F 20 73 69 20 65 73 20 6D 61 79 6F 72 20 64 65 20 36 34 30 4B 73}

	condition:
		all of them
}

rule webshell_NetworkFileManagerPHP
{
	meta:
		description = "Web Shell - file NetworkFileManagerPHP.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "acdbba993a5a4186fd864c5e4ea0ba4f"

	strings:
		$s9 = {20 20 65 63 68 6F 20 5C 22 3C 62 72 3E 3C 63 65 6E 74 65 72 3E 41 6C 6C 20 74 68 65 20 64 61 74 61 20 69 6E 20 74 68 65 73 65 20 74 61 62 6C 65 73 3A 3C 62 72 3E 20 5C 22 2E 24 74 62 6C 73 76 2E 5C 22 20 77 65 72 65 20 70 75 74 74 65 64 20}

	condition:
		all of them
}

rule webshell_Server_Variables
{
	meta:
		description = "Web Shell - file Server Variables.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "47fb8a647e441488b30f92b4d39003d7"

	strings:
		$s7 = {3C 25 20 46 6F 72 20 45 61 63 68 20 56 61 72 73 20 49 6E 20 52 65 71 75 65 73 74 2E 53 65 72 76 65 72 56 61 72 69 61 62 6C 65 73 20 25 3E}
		$s9 = {56 61 72 69 61 62 6C 65 20 4E 61 6D 65 3C 2F 42 3E 3C 2F 66 6F 6E 74 3E 3C 2F 70 3E}

	condition:
		all of them
}

rule webshell_caidao_shell_ice_2
{
	meta:
		description = "Web Shell - file ice.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1d6335247f58e0a5b03e17977888f5f2"

	strings:
		$s0 = {3C 3F 70 68 70 20 24 7B 24 7B 65 76 61 6C 28 24 5F 50 4F 53 54 5B 69 63 65 5D 29 7D 7D 3B 3F 3E}

	condition:
		all of them
}

rule webshell_caidao_shell_mdb
{
	meta:
		description = "Web Shell - file mdb.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fbf3847acef4844f3a0d04230f6b9ff9"

	strings:
		$s1 = {3C 25 20 65 78 65 63 75 74 65 20 72 65 71 75 65 73 74 28 5C 22 69 63 65 5C 22 29 25 3E 61 20}

	condition:
		all of them
}

rule webshell_jsp_guige
{
	meta:
		description = "Web Shell - file guige.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2c9f2dafa06332957127e2c713aacdd2"

	strings:
		$s0 = {69 66 28 64 61 6D 61 70 61 74 68 21 3D 6E 75 6C 6C 20 26 26 21 64 61 6D 61 70 61 74 68 2E 65 71 75 61 6C 73 28 5C 22 5C 22 29 26 26 63 6F 6E 74 65 6E 74 21 3D 6E 75 6C 6C}

	condition:
		all of them
}

rule webshell_phpspy2010
{
	meta:
		description = "Web Shell - file phpspy2010.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "14ae0e4f5349924a5047fed9f3b105c5"

	strings:
		$s3 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28}
		$s5 = {2F 2F 61 6E 67 65 6C}
		$s8 = {24 61 64 6D 69 6E 5B 27 63 6F 6F 6B 69 65 64 6F 6D 61 69 6E 27 5D 20 3D 20 27 27 3B}

	condition:
		all of them
}

rule webshell_asp_ice
{
	meta:
		description = "Web Shell - file ice.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d141e011a92f48da72728c35f1934a2b"

	strings:
		$s0 = {44 2C 27 50 72 6A 6B 6E 44 2C 4A 7E 5B 2C 45 64 6E 4D 50 5B 2C 2D 34 3B 44 53 36 40 23 40 26 56 4B 6F 62 78 32 6C 64 64 2C 27 7E 4A 68 43}

	condition:
		all of them
}

rule webshell_drag_system
{
	meta:
		description = "Web Shell - file system.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "15ae237cf395fb24cf12bff141fb3f7c"

	strings:
		$s9 = {53 74 72 69 6E 67 20 73 71 6C 20 3D 20 5C 22 53 45 4C 45 43 54 20 2A 20 46 52 4F 4D 20 44 42 41 5F 54 41 42 4C 45 53 20 57 48 45 52 45 20 54 41 42 4C 45 5F 4E 41 4D 45 20 6E 6F 74 20 6C 69 6B 65 20 27 25 24 25 27 20 61 6E 64 20 6E 75 6D 5F}

	condition:
		all of them
}

rule webshell_DarkBlade1_3_asp_indexx
{
	meta:
		description = "Web Shell - file indexx.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b7f46693648f534c2ca78e3f21685707"

	strings:
		$s3 = {43 6F 6E 73 74 20 73 74 72 73 5F 74 6F 54 72 61 6E 73 66 6F 72 6D 3D 5C 22 63 6F 6D 6D 61 6E 64 7C 52 61 64 6D 69 6E 7C 4E 54 41 75 54 68 65 6E 61 62 6C 65 64 7C 46 69 6C 74 65 72 49 70 7C 49 49 53 53 61 6D 70 6C 65 7C 50 61 67 65 43 6F 75}

	condition:
		all of them
}

rule webshell_phpshell3
{
	meta:
		description = "Web Shell - file phpshell3.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "76117b2ee4a7ac06832d50b2d04070b8"

	strings:
		$s2 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 6E 6F 75 6E 63 65 5C 22 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 24 5F 53 45 53 53 49 4F 4E 5B 27 6E 6F 75 6E 63 65 27 5D 3B}
		$s5 = {3C 70 3E 55 73 65 72 6E 61 6D 65 3A 20 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 75 73 65 72 6E 61 6D 65 5C 22 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 24 75 73 65 72 6E 61}
		$s7 = {24 5F 53 45 53 53 49 4F 4E 5B 27 6F 75 74 70 75 74 27 5D 20 2E 3D 20 5C 22 63 64 3A 20 63 6F 75 6C 64 20 6E 6F 74 20 63 68 61 6E 67 65 20 74 6F 3A 20 24 6E 65 77 5F 64 69 72 5C 5C 6E 5C 22 3B}

	condition:
		2 of them
}

rule webshell_jsp_hsxa
{
	meta:
		description = "Web Shell - file hsxa.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d0e05f9c9b8e0b3fa11f57d9ab800380"

	strings:
		$s0 = {3C 25 40 20 70 61 67 65 20 6C 61 6E 67 75 61 67 65 3D 5C 22 6A 61 76 61 5C 22 20 70 61 67 65 45 6E 63 6F 64 69 6E 67 3D 5C 22 67 62 6B 5C 22 25 3E 3C 6A 73 70 3A 64 69 72 65 63 74 69 76 65 2E 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61}

	condition:
		all of them
}

rule webshell_jsp_utils
{
	meta:
		description = "Web Shell - file utils.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9827ba2e8329075358b8e8a53e20d545"

	strings:
		$s0 = {52 65 73 75 6C 74 53 65 74 20 72 20 3D 20 63 2E 67 65 74 4D 65 74 61 44 61 74 61 28 29 2E 67 65 74 54 61 62 6C 65 73 28 6E 75 6C 6C 2C 20 6E 75 6C 6C 2C 20 5C 22 25 5C 22 2C 20 74 29 3B}
		$s4 = {53 74 72 69 6E 67 20 63 73 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A 30 5C 22 29 3D 3D 6E 75 6C 6C 3F 5C 22 67 62 6B 5C 22 3A 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A}

	condition:
		all of them
}

rule webshell_asp_01
{
	meta:
		description = "Web Shell - file 01.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 50
		hash = "61a687b0bea0ef97224c7bd2df118b87"

	strings:
		$s0 = {3C 25 65 76 61 6C 20 72 65 71 75 65 73 74 28 5C 22 70 61 73 73 5C 22 29 25 3E}

	condition:
		all of them
}

rule webshell_asp_404
{
	meta:
		description = "Web Shell - file 404.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d9fa1e8513dbf59fa5d130f389032a2d"

	strings:
		$s0 = {6C 46 79 77 36 70 64 5E 44 4B 56 5E 34 43 44 52 57 6D 6D 6E 4F 31 47 56 4B 44 6C 3A 79 26 20 66 2B 32}

	condition:
		all of them
}

rule webshell_webshell_cnseay02_1
{
	meta:
		description = "Web Shell - file webshell-cnseay02-1.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "95fc76081a42c4f26912826cb1bd24b1"

	strings:
		$s0 = {28 39 33 29 2E 24 5F 75 55 28 34 31 29 2E 24 5F 75 55 28 35 39 29 3B 24 5F 66 46 3D 24 5F 75 55 28 39 39 29 2E 24 5F 75 55 28 31 31 34 29 2E 24 5F 75 55 28 31 30 31 29 2E 24 5F 75 55 28 39 37 29 2E 24 5F 75 55 28 31 31 36 29 2E 24 5F 75 55}

	condition:
		all of them
}

rule webshell_php_fbi
{
	meta:
		description = "Web Shell - file fbi.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1fb32f8e58c8deb168c06297a04a21f1"

	strings:
		$s7 = {65 72 64 65 20 74 79 70 65 73 27 2C 27 47 65 74 61 6C 6C 65 6E 27 2C 27 44 61 74 75 6D 20 65 6E 20 74 69 6A 64 27 2C 27 54 65 6B 73 74 27 2C 27 42 69 6E 61 69 72 65 20 67 65 67 65 76 65 6E 73 27 2C 27 4E 65 74 77 65 72 6B 27 2C 27 47 65 6F}

	condition:
		all of them
}

rule webshell_B374kPHP_B374k
{
	meta:
		description = "Web Shell - file B374k.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "bed7388976f8f1d90422e8795dff1ea6"

	strings:
		$s0 = {48 74 74 70 3A 2F 2F 63 6F 64 65 2E 67 6F 6F 67 6C 65 2E 63 6F 6D 2F 70 2F 62 33 37 34 6B 2D 73 68 65 6C 6C}
		$s1 = {24 5F 3D 73 74 72 5F 72 6F 74 31 33 28 27 74 6D 27 2E 27 76 61 73 27 2E 27 79 6E 67 72 27 29 3B 24 5F 3D 73 74 72 5F 72 6F 74 31 33 28 73 74 72 72 65 76 28 27 72 71 62 27 2E 27 70 72 71 27 2E 27 5F 27 2E 27 34 36 72 27 2E 27 66 6E 6F 27}
		$s3 = {4A 61 79 61 6C 61 68 20 49 6E 64 6F 6E 65 73 69 61 6B 75 20 26 20 4C 79 6B 65 20 40 20 32 30 31 33}
		$s4 = {42 33 37 34 6B 20 56 69 70 20 49 6E 20 42 65 61 75 74 69 66 79 20 4A 75 73 74 20 46 6F 72 20 53 65 6C 66}

	condition:
		1 of them
}

rule webshell_cmd_asp_5_1
{
	meta:
		description = "Web Shell - file cmd-asp-5.1.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8baa99666bf3734cbdfdd10088e0cd9f"

	strings:
		$s9 = {43 61 6C 6C 20 6F 53 2E 52 75 6E 28 5C 22 77 69 6E 2E 63 6F 6D 20 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 5C 22 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 46 20 26}

	condition:
		all of them
}

rule webshell_php_dodo_zip
{
	meta:
		description = "Web Shell - file zip.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b7800364374077ce8864796240162ad5"

	strings:
		$s0 = {24 68 65 78 64 74 69 6D 65 20 3D 20 27 5C 5C 78 27 20 2E 20 24 64 74 69 6D 65 5B 36 5D 20 2E 20 24 64 74 69 6D 65 5B 37 5D 20 2E 20 27 5C 5C 78 27 20 2E 20 24 64 74 69 6D 65 5B 34 5D 20 2E 20 24 64 74 69 6D 65 5B 35 5D 20 2E 20 27 5C 5C 78}
		$s3 = {24 64 61 74 61 73 74 72 20 3D 20 5C 22 5C 5C 78 35 30 5C 5C 78 34 62 5C 5C 78 30 33 5C 5C 78 30 34 5C 5C 78 30 61 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30 5C 5C 78 30 30}

	condition:
		all of them
}

rule webshell_aZRaiLPhp_v1_0
{
	meta:
		description = "Web Shell - file aZRaiLPhp v1.0.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "26b2d3943395682e36da06ed493a3715"

	strings:
		$s5 = {65 63 68 6F 20 5C 22 20 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 27 23 30 30 30 30 46 46 27 3E 43 48 4D 4F 44 55 20 5C 22 2E 73 75 62 73 74 72 28 62 61 73 65 5F 63 6F 6E 76 65 72 74 28 40 66 69 6C 65 70 65 72 6D 73 28 24}
		$s7 = {65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 27 2E 2F 24 74 68 69 73 5F 66 69 6C 65 3F 6F 70 3D 65 66 70 26 66 6E 61 6D 65 3D 24 70 61 74 68 2F 24 66 69 6C 65 26 64 69 73 6D 69 3D 24 66 69 6C 65 26 79 6F 6C 3D 24 70 61 74 68 27 3E 3C 66 6F}

	condition:
		all of them
}

rule webshell_php_list
{
	meta:
		description = "Web Shell - file list.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "922b128ddd90e1dc2f73088956c548ed"

	strings:
		$s1 = {2F 2F 20 6C 69 73 74 2E 70 68 70 20 3D 20 44 69 72 65 63 74 6F 72 79 20 26 20 46 69 6C 65 20 4C 69 73 74 69 6E 67}
		$s2 = {20 20 20 20 65 63 68 6F 20 5C 22 28 20 29 20 3C 61 20 68 72 65 66 3D 3F 66 69 6C 65 3D 5C 22 20 2E 20 24 66 69 63 68 65 72 6F 20 2E 20 5C 22 2F 5C 22 20 2E 20 24 66 69 6C 65 6E 61 6D 65 20 2E 20 5C 22 3E 5C 22 20 2E 20 24 66 69 6C 65 6E 61}
		$s9 = {2F 2F 20 62 79 3A 20 54 68 65 20 44 61 72 6B 20 52 61 76 65 72}

	condition:
		1 of them
}

rule webshell_ironshell
{
	meta:
		description = "Web Shell - file ironshell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8bfa2eeb8a3ff6afc619258e39fded56"

	strings:
		$s4 = {70 72 69 6E 74 20 5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 5C 22 2E 24 6D 65 2E 5C 22 3F 70 3D 63 6D 64 26 64 69 72 3D 5C 22 2E 72 65 61 6C 70 61 74 68 28 27 2E 27 29 2E 5C 22}
		$s8 = {70 72 69 6E 74 20 5C 22 3C 74 64 20 69 64 3D 66 3E 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 3F 70 3D 72 65 6E 61 6D 65 26 66 69 6C 65 3D 5C 22 2E 72 65 61 6C 70 61 74 68 28 24 66 69 6C 65 29 2E 5C 22 26 64 69}

	condition:
		all of them
}

rule webshell_caidao_shell_404
{
	meta:
		description = "Web Shell - file 404.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ee94952dc53d9a29bdf4ece54c7a7aa7"

	strings:
		$s0 = {3C 3F 70 68 70 20 24 4B 3D 73 54 72 5F 52 65 70 4C 61 43 65 28 27 60 27 2C 27 27 2C 27 61 60 73 60 73 60 65 60 72 60 74 27 29 3B 24 4D 3D 24 5F 50 4F 53 54 5B 69 63 65 5D 3B 49 46 28 24 4D 3D 3D 4E 75 4C 6C 29 48 65 61 44 65 52 28 27 53 74}

	condition:
		all of them
}

rule webshell_ASP_aspydrv
{
	meta:
		description = "Web Shell - file aspydrv.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "de0a58f7d1e200d0b2c801a94ebce330"

	strings:
		$s3 = {3C 25 3D 74 68 69 6E 67 79 2E 44 72 69 76 65 4C 65 74 74 65 72 25 3E 20 3C 2F 74 64 3E 3C 74 64 3E 3C 74 74 3E 20 3C 25 3D 74 68 69 6E 67 79 2E 44 72 69 76 65 54 79 70 65 25 3E 20 3C 2F 74 64 3E 3C 74 64 3E 3C 74 74 3E 20 3C 25 3D 74 68 69}

	condition:
		all of them
}

rule webshell_jsp_web
{
	meta:
		description = "Web Shell - file web.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "4bc11e28f5dccd0c45a37f2b541b2e98"

	strings:
		$s0 = {3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 69 6F 2E 2A 5C 22 25 3E 3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 6E 65 74 2E 2A 5C 22 25 3E 3C 25 53 74 72 69 6E 67 20 74 3D 72 65 71 75 65 73 74 2E}

	condition:
		all of them
}

rule webshell_mysqlwebsh
{
	meta:
		description = "Web Shell - file mysqlwebsh.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "babfa76d11943a22484b3837f105fada"

	strings:
		$s3 = {20 3C 54 52 3E 3C 54 44 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 3F 20 65 63 68 6F 20 28 21 24 43 4F 4E 4E 45 43 54 20 26 26 20 24 61 63 74 69 6F 6E 20 3D 3D 20 5C 22 63 68 70 61 72 61 6D 5C 22 29 3F 5C 22 23 36 36 30 30 30 30 5C 22 3A 5C 22 23}

	condition:
		all of them
}

rule webshell_jspShell
{
	meta:
		description = "Web Shell - file jspShell.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0d5b5a17552254be6c1c8f1eb3a5fdc1"

	strings:
		$s0 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 63 68 65 63 6B 62 6F 78 5C 22 20 6E 61 6D 65 3D 5C 22 61 75 74 6F 55 70 64 61 74 65 5C 22 20 76 61 6C 75 65 3D 5C 22 41 75 74 6F 55 70 64 61 74 65 5C 22 20 6F 6E}
		$s1 = {6F 6E 62 6C 75 72 3D 5C 22 64 6F 63 75 6D 65 6E 74 2E 73 68 65 6C 6C 2E 61 75 74 6F 55 70 64 61 74 65 2E 63 68 65 63 6B 65 64 3D 20 74 68 69 73 2E 6F 6C 64 56 61 6C 75 65 3B}

	condition:
		all of them
}

rule webshell_Dx_Dx
{
	meta:
		description = "Web Shell - file Dx.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9cfe372d49fe8bf2fac8e1c534153d9b"

	strings:
		$s1 = {70 72 69 6E 74 20 5C 22 5C 5C 6E 5C 22 2E 27 54 69 70 3A 20 74 6F 20 76 69 65 77 20 74 68 65 20 66 69 6C 65 20 5C 22 61 73 20 69 73 5C 22 20 2D 20 6F 70 65 6E 20 74 68 65 20 70 61 67 65 20 69 6E 20 3C 61 20 68 72 65 66 3D 5C 22 27 2E 44 78}
		$s9 = {63 6C 61 73 73 3D 6C 69 6E 65 6C 69 73 74 69 6E 67 3E 3C 6E 6F 62 72 3E 50 4F 53 54 20 28 70 68 70 20 65 76 61 6C 29 3C 2F 74 64 3E 3C}

	condition:
		1 of them
}

rule webshell_asp_ntdaddy
{
	meta:
		description = "Web Shell - file ntdaddy.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c5e6baa5d140f73b4e16a6cfde671c68"

	strings:
		$s9 = {69 66 20 20 46 50 20 20 3D 20 20 5C 22 52 65 66 72 65 73 68 46 6F 6C 64 65 72 5C 22 20 20 6F 72 20 20}
		$s10 = {72 65 71 75 65 73 74 2E 66 6F 72 6D 28 5C 22 63 6D 64 4F 70 74 69 6F 6E 5C 22 29 3D 5C 22 44 65 6C 65 74 65 46 6F 6C 64 65 72 5C 22 20 20}

	condition:
		1 of them
}

rule webshell_MySQL_Web_Interface_Version_0_8
{
	meta:
		description = "Web Shell - file MySQL Web Interface Version 0.8.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "36d4f34d0a22080f47bb1cb94107c60f"

	strings:
		$s2 = {68 72 65 66 3D 27 24 50 48 50 5F 53 45 4C 46 3F 61 63 74 69 6F 6E 3D 64 75 6D 70 54 61 62 6C 65 26 64 62 6E 61 6D 65 3D 24 64 62 6E 61 6D 65 26 74 61 62 6C 65 6E 61 6D 65 3D 24 74 61 62 6C 65 6E 61 6D 65 27 3E 44 75 6D 70 3C 2F 61 3E}

	condition:
		all of them
}

rule webshell_elmaliseker_2
{
	meta:
		description = "Web Shell - file elmaliseker.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"

	strings:
		$s1 = {3C 74 64 3C 25 69 66 20 28 46 53 4F 2E 47 65 74 45 78 74 65 6E 73 69 6F 6E 4E 61 6D 65 28 70 61 74 68 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 46 69 6C 65 2E 4E 61 6D 65 29 3D 5C 22 6C 6E 6B 5C 22 29 20 6F 72 20 28 46 53 4F 2E 47 65 74 45 78}
		$s6 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 62 75 74 74 6F 6E 20 76 61 6C 75 65 3D 53 61 76 65 20 6F 6E 63 6C 69 63 6B 3D 5C 22 45 64 69 74 6F 72 43 6F 6D 6D 61 6E 64 28 27 53 61 76 65 27 29 5C 22 3E 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 62 75 74}

	condition:
		all of them
}

rule webshell_ASP_RemExp
{
	meta:
		description = "Web Shell - file RemExp.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aa1d8491f4e2894dbdb91eec1abc2244"

	strings:
		$s0 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 74 69 74 6C 65 3D 5C 22 3C 25 3D 53 75 62 46 6F 6C 64 65 72 2E 4E 61 6D 65 25 3E 5C 22 3E 20 3C 61 20 68 72 65 66 3D 20 5C 22 3C 25 3D 52 65 71 75 65 73}
		$s1 = {50 72 69 76 61 74 65 20 46 75 6E 63 74 69 6F 6E 20 43 6F 6E 76 65 72 74 42 69 6E 61 72 79 28 42 79 56 61 6C 20 53 6F 75 72 63 65 4E 75 6D 62 65 72 2C 20 42 79 56 61 6C 20 4D 61 78 56 61 6C 75 65 50 65 72 49 6E 64 65 78 2C 20 42 79 56 61 6C}

	condition:
		all of them
}

rule webshell_jsp_list1
{
	meta:
		description = "Web Shell - file list1.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8d9e5afa77303c9c01ff34ea4e7f6ca6"

	strings:
		$s1 = {63 61 73 65 20 27 73 27 3A 43 6F 6E 6E 65 63 74 69 6F 6E 44 42 4D 28 6F 75 74 2C 65 6E 63 6F 64 65 43 68 61 6E 67 65 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 64 72 69 76 65}
		$s9 = {72 65 74 75 72 6E 20 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 64 65 6C 46 69 6C 65 28 27 5C 22 2B 66 6F 6C 64 65 72 52 65 70 6C 61 63 65 28 66 69 6C 65 29 2B 5C 22 27 29 5C 5C 5C 22}

	condition:
		all of them
}

rule webshell_phpkit_1_0_odd
{
	meta:
		description = "Web Shell - file odd.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "594d1b1311bbef38a0eb3d6cbb1ab538"

	strings:
		$s0 = {69 6E 63 6C 75 64 65 28 27 70 68 70 3A 2F 2F 69 6E 70 75 74 27 29 3B}
		$s1 = {2F 2F 20 4E 6F 20 65 76 61 6C 28 29 20 63 61 6C 6C 73 2C 20 6E 6F 20 73 79 73 74 65 6D 28 29 20 63 61 6C 6C 73 2C 20 6E 6F 74 68 69 6E 67 20 6E 6F 72 6D 61 6C 6C 79 20 73 65 65 6E 20 61 73 20 6D 61 6C 69 63 69 6F 75 73 2E}
		$s2 = {69 6E 69 5F 73 65 74 28 27 61 6C 6C 6F 77 5F 75 72 6C 5F 69 6E 63 6C 75 64 65 2C 20 31 27 29 3B 20 2F 2F 20 41 6C 6C 6F 77 20 75 72 6C 20 69 6E 63 6C 75 73 69 6F 6E 20 69 6E 20 74 68 69 73 20 73 63 72 69 70 74}

	condition:
		all of them
}

rule webshell_jsp_123
{
	meta:
		description = "Web Shell - file 123.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c691f53e849676cac68a38d692467641"

	strings:
		$s0 = {3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 62 6C 75 65 5C 22 3E 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3A 3C 2F 66 6F 6E 74 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 73 69 7A 65 3D 5C 22 37}
		$s3 = {53 74 72 69 6E 67 20 70 61 74 68 3D 6E 65 77 20 53 74 72 69 6E 67 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 74 68 5C 22 29 2E 67 65 74 42 79 74 65 73 28 5C 22 49 53 4F 2D 38 38 35 39 2D 31 5C 22}
		$s9 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 6E 61 6D 65 3D 5C 22 62 74 6E 53 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 55 70 6C 6F 61 64 5C 22 3E 20 20 20 20}

	condition:
		all of them
}

rule webshell_asp_1
{
	meta:
		description = "Web Shell - file 1.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8991148adf5de3b8322ec5d78cb01bdb"

	strings:
		$s4 = {21 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32}
		$s8 = {3C 25 65 76 61 6C 20 72 65 71 75 65 73 74 28 5C 22 70 61 73 73 5C 22 29 25 3E}

	condition:
		all of them
}

rule webshell_ASP_tool
{
	meta:
		description = "Web Shell - file tool.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "4ab68d38527d5834e9c1ff64407b34fb"

	strings:
		$s0 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 46 4F 52 4D 20 61 63 74 69 6F 6E 3D 5C 22 5C 22 5C 22 20 26 20 52 65 71 75 65 73 74 2E 53 65 72 76 65 72 56 61 72 69 61 62 6C 65 73 28 5C 22 55 52 4C 5C 22 29 20 26 20 5C 22 5C 22 5C 22}
		$s3 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 74 72 3E 3C 74 64 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 27 61 72 69 61 6C 27 20 73 69 7A 65 3D 27 32 27 3E 3C 62 3E 26 6C 74 3B 44 49 52 26 67 74 3B 20 3C 61 20 68 72 65 66 3D 27 5C 22 20}
		$s9 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 27 61 72 69 61 6C 27 20 73 69 7A 65 3D 27 31 27 3E 3C 61 20 68 72 65 66 3D 5C 22 5C 22 23 5C 22 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 22 5C 22 6A 61 76 61 73}

	condition:
		2 of them
}

rule webshell_cmd_win32
{
	meta:
		description = "Web Shell - file cmd_win32.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "cc4d4d6cc9a25984aa9a7583c7def174"

	strings:
		$s0 = {50 72 6F 63 65 73 73 20 70 20 3D 20 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 2B 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D}
		$s1 = {3C 46 4F 52 4D 20 4D 45 54 48 4F 44 3D 5C 22 50 4F 53 54 5C 22 20 4E 41 4D 45 3D 5C 22 6D 79 66 6F 72 6D 5C 22 20 41 43 54 49 4F 4E 3D 5C 22 5C 22 3E}

	condition:
		2 of them
}

rule webshell_jsp_jshell
{
	meta:
		description = "Web Shell - file jshell.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "124b22f38aaaf064cef14711b2602c06"

	strings:
		$s0 = {6B 58 70 65 57 5B 5C 22}
		$s4 = {5B 37 62 3A 67 30 57 40 57 3C}
		$s5 = {62 3A 67 48 72 2C 67 3C}
		$s8 = {52 68 56 30 57 40 57 3C}
		$s9 = {53 5F 4D 52 28 75 37 62}

	condition:
		all of them
}

rule webshell_ASP_zehir4
{
	meta:
		description = "Web Shell - file zehir4.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "7f4e12e159360743ec016273c3b9108c"

	strings:
		$s9 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 61 20 68 72 65 66 3D 27 5C 22 26 64 6F 73 79 61 50 61 74 68 26 5C 22 3F 73 74 61 74 75 73 3D 37 26 50 61 74 68 3D 5C 22 26 50 61 74 68 26 5C 22 2F}

	condition:
		all of them
}

rule webshell_wsb_idc
{
	meta:
		description = "Web Shell - file idc.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "7c5b1b30196c51f1accbffb80296395f"

	strings:
		$s1 = {69 66 20 28 6D 64 35 28 24 5F 47 45 54 5B 27 75 73 72 27 5D 29 3D 3D 24 75 73 65 72 20 26 26 20 6D 64 35 28 24 5F 47 45 54 5B 27 70 61 73 73 27 5D 29 3D 3D 24 70 61 73 73 29}
		$s3 = {7B 65 76 61 6C 28 24 5F 47 45 54 5B 27 69 64 63 27 5D 29 3B 7D}

	condition:
		1 of them
}

rule webshell_cpg_143_incl_xpl
{
	meta:
		description = "Web Shell - file cpg_143_incl_xpl.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5937b131b67d8e0afdbd589251a5e176"

	strings:
		$s3 = {24 64 61 74 61 3D 5C 22 75 73 65 72 6E 61 6D 65 3D 5C 22 2E 75 72 6C 65 6E 63 6F 64 65 28 24 55 53 45 52 29 2E 5C 22 26 70 61 73 73 77 6F 72 64 3D 5C 22 2E 75 72 6C 65 6E 63 6F 64 65 28 24 50 41}
		$s5 = {66 70 75 74 73 28 24 73 75 6E 5F 74 7A 75 2C 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 5C 5C 5C 22 48 69 20 4D 61 73 74 65 72 21 5C 5C 5C 22 3B 69 6E 69 5F 73 65 74 28 5C 5C 5C 22 6D 61 78 5F 65 78 65 63 75 74 69 6F 6E 5F 74 69 6D 65}

	condition:
		1 of them
}

rule webshell_mumaasp_com
{
	meta:
		description = "Web Shell - file mumaasp.com.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "cce32b2e18f5357c85b6d20f564ebd5d"

	strings:
		$s0 = {26 39 4B 5F 29 50 38 32 61 69 2C 41 7D 49 39 32 5D 52 5C 22 71 21 43 3A 52 5A 7D 53 36 5D 3D 50 61 54 54 52}

	condition:
		all of them
}

rule webshell_php_404
{
	meta:
		description = "Web Shell - file 404.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ced050df5ca42064056a7ad610a191b3"

	strings:
		$s0 = {24 70 61 73 73 20 3D 20 6D 64 35 28 6D 64 35 28 6D 64 35 28 24 70 61 73 73 29 29 29 3B}

	condition:
		all of them
}

rule webshell_webshell_cnseay_x
{
	meta:
		description = "Web Shell - file webshell-cnseay-x.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a0f9f7f5cd405a514a7f3be329f380e5"

	strings:
		$s9 = {24 5F 46 5F 46 2E 3D 27 5F 27 2E 24 5F 50 5F 50 5B 35 5D 2E 24 5F 50 5F 50 5B 32 30 5D 2E 24 5F 50 5F 50 5B 31 33 5D 2E 24 5F 50 5F 50 5B 32 5D 2E 24 5F 50 5F 50 5B 31 39 5D 2E 24 5F 50 5F 50 5B 38 5D 2E 24 5F 50 5F}

	condition:
		all of them
}

rule webshell_asp_up
{
	meta:
		description = "Web Shell - file up.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "f775e721cfe85019fe41c34f47c0d67c"

	strings:
		$s0 = {50 6F 73 20 3D 20 49 6E 73 74 72 42 28 42 6F 75 6E 64 61 72 79 50 6F 73 2C 52 65 71 75 65 73 74 42 69 6E 2C 67 65 74 42 79 74 65 53 74 72 69 6E 67 28 5C 22 43 6F 6E 74 65 6E 74 2D 44 69 73 70 6F 73 69 74 69 6F}
		$s1 = {43 6F 6E 74 65 6E 74 54 79 70 65 20 3D 20 67 65 74 53 74 72 69 6E 67 28 4D 69 64 42 28 52 65 71 75 65 73 74 42 69 6E 2C 50 6F 73 42 65 67 2C 50 6F 73 45 6E 64 2D 50 6F 73 42 65 67 29 29}

	condition:
		1 of them
}

rule webshell_phpkit_0_1a_odd
{
	meta:
		description = "Web Shell - file odd.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3c30399e7480c09276f412271f60ed01"

	strings:
		$s1 = {69 6E 63 6C 75 64 65 28 27 70 68 70 3A 2F 2F 69 6E 70 75 74 27 29 3B}
		$s3 = {69 6E 69 5F 73 65 74 28 27 61 6C 6C 6F 77 5F 75 72 6C 5F 69 6E 63 6C 75 64 65 2C 20 31 27 29 3B 20 2F 2F 20 41 6C 6C 6F 77 20 75 72 6C 20 69 6E 63 6C 75 73 69 6F 6E 20 69 6E 20 74 68 69 73 20 73 63 72 69 70 74}
		$s4 = {2F 2F 20 75 73 65 73 20 69 6E 63 6C 75 64 65 28 27 70 68 70 3A 2F 2F 69 6E 70 75 74 27 29 20 74 6F 20 65 78 65 63 75 74 65 20 61 72 62 72 69 74 61 72 79 20 63 6F 64 65}
		$s5 = {2F 2F 20 70 68 70 3A 2F 2F 69 6E 70 75 74 20 62 61 73 65 64 20 62 61 63 6B 64 6F 6F 72}

	condition:
		2 of them
}

rule webshell_ASP_cmd
{
	meta:
		description = "Web Shell - file cmd.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "97af88b478422067f23b001dd06d56a9"

	strings:
		$s0 = {3C 25 3D 20 5C 22 5C 5C 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 55 73 65 72 4E 61 6D 65 20 25 3E}

	condition:
		all of them
}

rule webshell_PHP_Shell_x3
{
	meta:
		description = "Web Shell - file PHP Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"

	strings:
		$s4 = {26 6E 62 73 70 3B 26 6E 62 73 70 3B 3C 3F 70 68 70 20 65 63 68 6F 20 62 75 69 6C 64 55 72 6C 28 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 5C 5C 22 6E 61 76 79 5C 5C 5C 22 3E 5B}
		$s6 = {65 63 68 6F 20 5C 22 3C 2F 66 6F 72 6D 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 24 53 46 69 6C 65 4E 61 6D 65 3F 24 75 72 6C 41 64 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 70 6F 73 74 5C 5C 5C 22 3E 3C 69 6E 70 75 74}
		$s9 = {69 66 20 20 28 20 28 20 28 69 73 73 65 74 28 24 68 74 74 70 5F 61 75 74 68 5F 75 73 65 72 29 20 29 20 26 26 20 28 69 73 73 65 74 28 24 68 74 74 70 5F 61 75 74 68 5F 70 61 73 73 29 29 20 29 20 26 26 20 28 20 21 69 73 73 65 74 28}

	condition:
		2 of them
}

rule webshell_PHP_g00nv13
{
	meta:
		description = "Web Shell - file g00nv13.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "35ad2533192fe8a1a76c3276140db820"

	strings:
		$s1 = {63 61 73 65 20 5C 22 7A 69 70 5C 22 3A 20 63 61 73 65 20 5C 22 74 61 72 5C 22 3A 20 63 61 73 65 20 5C 22 72 61 72 5C 22 3A 20 63 61 73 65 20 5C 22 67 7A 5C 22 3A 20 63 61 73 65 20 5C 22 63 61 62 5C 22 3A 20 63 61 73}
		$s4 = {69 66 28 21 28 24 73 71 6C 63 6F 6E 20 3D 20 40 6D 79 73 71 6C 5F 63 6F 6E 6E 65 63 74 28 24 5F 53 45 53 53 49 4F 4E 5B 27 73 71 6C 5F 68 6F 73 74 27 5D 20 2E 20 27 3A 27 20 2E 20 24 5F 53 45 53 53 49 4F 4E 5B 27 73 71 6C 5F 70}

	condition:
		all of them
}

rule webshell_php_h6ss
{
	meta:
		description = "Web Shell - file h6ss.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "272dde9a4a7265d6c139287560328cd5"

	strings:
		$s0 = {3C 3F 70 68 70 20 65 76 61 6C 28 67 7A 75 6E 63 6F 6D 70 72 65 73 73 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 5C 22}

	condition:
		all of them
}

rule webshell_jsp_zx
{
	meta:
		description = "Web Shell - file zx.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "67627c264db1e54a4720bd6a64721674"

	strings:
		$s0 = {69 66 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 5C 22 29 21 3D 6E 75 6C 6C 29 28 6E 65 77 20 6A 61 76 61 2E 69 6F 2E 46 69 6C 65 4F 75 74 70 75 74 53 74 72 65 61 6D 28 61 70 70 6C 69 63 61 74 69 6F 6E 2E 67}

	condition:
		all of them
}

rule webshell_Ani_Shell
{
	meta:
		description = "Web Shell - file Ani-Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "889bfc9fbb8ee7832044fc575324d01a"

	strings:
		$s0 = {24 50 79 74 68 6F 6E 5F 43 4F 44 45 20 3D 20 5C 22 49}
		$s6 = {24 70 61 73 73 77 6F 72 64 50 72 6F 6D 70 74 20 3D 20 5C 22 5C 5C 6E 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D}
		$s7 = {66 70 75 74 73 20 28 24 73 6F 63 6B 66 64 20 2C 5C 22 5C 5C 6E 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D}

	condition:
		1 of them
}

rule webshell_jsp_k8cmd
{
	meta:
		description = "Web Shell - file k8cmd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b39544415e692a567455ff033a97a682"

	strings:
		$s2 = {69 66 28 72 65 71 75 65 73 74 2E 67 65 74 53 65 73 73 69 6F 6E 28 29 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 68 65 68 65 5C 22 29 2E 74 6F 53 74 72 69 6E 67 28 29 2E 65 71 75 61 6C 73 28 5C 22 68 65 68 65 5C 22 29 29}

	condition:
		all of them
}

rule webshell_jsp_cmd
{
	meta:
		description = "Web Shell - file cmd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5391c4a8af1ede757ba9d28865e75853"

	strings:
		$s6 = {6F 75 74 2E 70 72 69 6E 74 6C 6E 28 5C 22 43 6F 6D 6D 61 6E 64 3A 20 5C 22 20 2B 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 63 6D 64 5C 22 29 20 2B 20 5C 22 3C 42 52 3E 5C 22 29 3B}

	condition:
		all of them
}

rule webshell_jsp_k81
{
	meta:
		description = "Web Shell - file k81.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "41efc5c71b6885add9c1d516371bd6af"

	strings:
		$s1 = {62 79 74 65 5B 5D 20 62 69 6E 61 72 79 20 3D 20 42 41 53 45 36 34 44 65 63 6F 64 65 72 2E 63 6C 61 73 73 2E 6E 65 77 49 6E 73 74 61 6E 63 65 28 29 2E 64 65 63 6F 64 65 42 75 66 66 65 72 28 63 6D 64 29 3B}
		$s9 = {69 66 28 63 6D 64 2E 65 71 75 61 6C 73 28 5C 22 53 7A 68 30 5A 57 46 74 5C 22 29 29 7B 6F 75 74 2E 70 72 69 6E 74 28 5C 22 5B 53 5D 5C 22 2B 64 69 72 2B 5C 22 5B 45 5D 5C 22 29 3B 7D}

	condition:
		1 of them
}

rule webshell_ASP_zehir
{
	meta:
		description = "Web Shell - file zehir.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0061d800aee63ccaf41d2d62ec15985d"

	strings:
		$s9 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 77 69 6E 67 64 69 6E 67 73 20 73 69 7A 65 3D 33 3E 3C 61 20 68 72 65 66 3D 27 5C 22 26 64 6F 73 79 61 50 61 74 68 26 5C 22 3F 73 74 61 74 75 73 3D 31 38 26}

	condition:
		all of them
}

rule webshell_Worse_Linux_Shell
{
	meta:
		description = "Web Shell - file Worse Linux Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8338c8d9eab10bd38a7116eb534b5fa2"

	strings:
		$s0 = {73 79 73 74 65 6D 28 5C 22 6D 76 20 5C 22 2E 24 5F 46 49 4C 45 53 5B 27 5F 75 70 6C 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2E 5C 22 20 5C 22 2E 24 63 75 72 72 65 6E 74 57 44}

	condition:
		all of them
}

rule webshell_zacosmall
{
	meta:
		description = "Web Shell - file zacosmall.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5295ee8dc2f5fd416be442548d68f7a6"

	strings:
		$s0 = {69 66 28 24 63 6D 64 21 3D 3D 27 27 29 7B 20 65 63 68 6F 28 27 3C 73 74 72 6F 6E 67 3E 27 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 63 6D 64 29 2E 5C 22 3C 2F 73 74 72 6F 6E 67 3E 3C 68 72 3E}

	condition:
		all of them
}

rule webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit
{
	meta:
		description = "Web Shell - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"

	strings:
		$s1 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 63 61 74 20 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 3E 2F 65 74 63 2F 70 61 73 73 77 64 3C 2F 6F 70 74 69 6F 6E 3E}

	condition:
		all of them
}

rule webshell_redirect
{
	meta:
		description = "Web Shell - file redirect.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "97da83c6e3efbba98df270cc70beb8f8"

	strings:
		$s7 = {76 61 72 20 66 6C 61 67 20 3D 20 5C 22 3F 74 78 74 3D 5C 22 20 2B 20 28 64 6F 63 75 6D 65 6E 74 2E 67 65 74 45 6C 65 6D 65 6E 74 42 79 49 64 28 5C 22 64 6C 5C 22 29 2E 63 68 65 63 6B 65 64 20 3F 20 5C 22 32 5C 22 3A 5C 22 31 5C 22 20}

	condition:
		all of them
}

rule webshell_jsp_cmdjsp
{
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b815611cc39f17f05a73444d699341d4"

	strings:
		$s5 = {3C 46 4F 52 4D 20 4D 45 54 48 4F 44 3D 47 45 54 20 41 43 54 49 4F 4E 3D 27 63 6D 64 6A 73 70 2E 6A 73 70 27 3E}

	condition:
		all of them
}

rule webshell_Java_Shell
{
	meta:
		description = "Web Shell - file Java Shell.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "36403bc776eb12e8b7cc0eb47c8aac83"

	strings:
		$s4 = {70 75 62 6C 69 63 20 4A 79 74 68 6F 6E 53 68 65 6C 6C 28 69 6E 74 20 63 6F 6C 75 6D 6E 73 2C 20 69 6E 74 20 72 6F 77 73 2C 20 69 6E 74 20 73 63 72 6F 6C 6C 62 61 63 6B 29 20 7B}
		$s9 = {74 68 69 73 28 6E 75 6C 6C 2C 20 50 79 2E 67 65 74 53 79 73 74 65 6D 53 74 61 74 65 28 29 2C 20 63 6F 6C 75 6D 6E 73 2C 20 72 6F 77 73 2C 20 73 63 72 6F 6C 6C 62 61 63 6B 29 3B}

	condition:
		1 of them
}

rule webshell_asp_1d
{
	meta:
		description = "Web Shell - file 1d.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fad7504ca8a55d4453e552621f81563c"

	strings:
		$s0 = {2B 39 4A 6B 73 6B 4F 66 4B 68 55 78 5A 4A 50 4C 7E 5C 5C 28 6D 44 5E 57 7E 5B 2C 7B 40 23 40 26 45 4F}

	condition:
		all of them
}

// duplicated
/* rule webshell_jsp_IXRbE
{
	meta:
		description = "Web Shell - file IXRbE.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e26e7e0ebc6e7662e1123452a939e2cd"

	strings:
		$s0 = {3C 25 69 66 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 5C 22 29 21 3D 6E 75 6C 6C 29 28 6E 65 77 20 6A 61 76 61 2E 69 6F 2E 46 69 6C 65 4F 75 74 70 75 74 53 74 72 65 61 6D 28 61 70 70 6C 69 63 61 74 69 6F 6E}

	condition:
		all of them
}*/

rule webshell_PHP_G5
{
	meta:
		description = "Web Shell - file G5.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "95b4a56140a650c74ed2ec36f08d757f"

	strings:
		$s3 = {65 63 68 6F 20 5C 22 48 61 63 6B 69 6E 67 20 4D 6F 64 65 3F 3C 62 72 3E 3C 73 65 6C 65 63 74 20 6E 61 6D 65 3D 27 68 74 79 70 65 27 3E 3C 6F 70 74 69 6F 6E 20 3E 2D 2D 2D 2D 2D 2D 2D 2D 53 45 4C 45 43 54 2D 2D 2D 2D 2D 2D 2D 2D 3C 2F 6F 70}

	condition:
		all of them
}

rule webshell_PHP_r57142
{
	meta:
		description = "Web Shell - file r57142.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0911b6e6b8f4bcb05599b2885a7fe8a8"

	strings:
		$s0 = {24 64 6F 77 6E 6C 6F 61 64 65 72 73 20 3D 20 61 72 72 61 79 28 27 77 67 65 74 27 2C 27 66 65 74 63 68 27 2C 27 6C 79 6E 78 27 2C 27 6C 69 6E 6B 73 27 2C 27 63 75 72 6C 27 2C 27 67 65 74 27 2C 27 6C 77 70 2D 6D 69 72 72 6F 72 27 29 3B}

	condition:
		all of them
}

rule webshell_jsp_tree
{
	meta:
		description = "Web Shell - file tree.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "bcdf7bbf7bbfa1ffa4f9a21957dbcdfa"

	strings:
		$s5 = {24 28 27 23 74 74 32 27 29 2E 74 72 65 65 28 27 6F 70 74 69 6F 6E 73 27 29 2E 75 72 6C 20 3D 20 5C 22 73 65 6C 65 63 74 43 68 69 6C 64 2E 61 63 74 69 6F 6E 3F 63 68 65 63 6B 69}
		$s6 = {53 74 72 69 6E 67 20 62 61 73 65 50 61 74 68 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 53 63 68 65 6D 65 28 29 2B 5C 22 3A 2F 2F 5C 22 2B 72 65 71 75 65 73 74 2E 67 65 74 53 65 72 76 65 72 4E 61 6D 65 28 29 2B 5C 22 3A 5C 22 2B 72 65 71 75}

	condition:
		all of them
}

rule webshell_C99madShell_v_3_0_smowu
{
	meta:
		description = "Web Shell - file smowu.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "74e1e7c7a6798f1663efb42882b85bee"

	strings:
		$s2 = {3C 74 72 3E 3C 74 64 20 77 69 64 74 68 3D 5C 22 35 30 25 5C 22 20 68 65 69 67 68 74 3D 5C 22 31 5C 22 20 76 61 6C 69 67 6E 3D 5C 22 74 6F 70 5C 22 3E 3C 63 65 6E 74 65 72 3E 3C 62 3E 3A 3A 20 45 6E 74 65 72 20 3A 3A 3C 2F 62 3E 3C 66 6F 72}
		$s8 = {3C 70 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 57 6F 72 64 70 72 65 73 73 20 4E 6F 74 20 46 6F 75 6E 64 21 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 74 65 78 74 20 69 64 3D 5C 22 77 70 5F 70 61 74 5C 22 3E 3C 69 6E 70 75 74 20 74 79}

	condition:
		1 of them
}

rule webshell_simple_backdoor
{
	meta:
		description = "Web Shell - file simple-backdoor.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "f091d1b9274c881f8e41b2f96e6b9936"

	strings:
		$s0 = {24 63 6D 64 20 3D 20 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 3B}
		$s1 = {69 66 28 69 73 73 65 74 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 29 7B}
		$s4 = {73 79 73 74 65 6D 28 24 63 6D 64 29 3B}

	condition:
		2 of them
}

rule webshell_PHP_404
{
	meta:
		description = "Web Shell - file 404.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "078c55ac475ab9e028f94f879f548bca"

	strings:
		$s4 = {3C 73 70 61 6E 3E 50 6F 73 69 78 5F 67 65 74 70 77 75 69 64 20 28 5C 22 52 65 61 64 5C 22 20 2F 65 74 63 2F 70 61 73 73 77 64 29}

	condition:
		all of them
}

rule webshell_Macker_s_Private_PHPShell
{
	meta:
		description = "Web Shell - file Macker's Private PHPShell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e24cbf0e294da9ac2117dc660d890bb9"

	strings:
		$s3 = {65 63 68 6F 20 5C 22 3C 74 72 3E 3C 74 64 20 63 6C 61 73 73 3D 5C 5C 5C 22 73 69 6C 76 65 72 20 62 6F 72 64 65 72 5C 5C 5C 22 3E 26 6E 62 73 70 3B 3C 73 74 72 6F 6E 67 3E 53 65 72 76 65 72 27 73 20 50 48 50 20 56 65 72 73 69 6F 6E 3A 26 6E}
		$s4 = {26 6E 62 73 70 3B 26 6E 62 73 70 3B 3C 3F 70 68 70 20 65 63 68 6F 20 62 75 69 6C 64 55 72 6C 28 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 5C 5C 22 6E 61 76 79 5C 5C 5C 22 3E 5B}
		$s7 = {65 63 68 6F 20 5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 24 53 46 69 6C 65 4E 61 6D 65 3F 24 75 72 6C 41 64 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50 4F 53 54 5C 5C 5C 22 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D}

	condition:
		all of them
}

rule webshell_Antichat_Shell_v1_3_2
{
	meta:
		description = "Web Shell - file Antichat Shell v1.3.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "40d0abceba125868be7f3f990f031521"

	strings:
		$s3 = {24 68 65 61 64 65 72 3D 27 3C 68 74 6D 6C 3E 3C 68 65 61 64 3E 3C 74 69 74 6C 65 3E 27 2E 67 65 74 65 6E 76 28 5C 22 48 54 54 50 5F 48 4F 53 54 5C 22 29 2E 27 20 2D 20 41 6E 74 69 63 68 61 74 20 53 68 65 6C 6C 3C 2F 74 69 74 6C 65 3E 3C 6D}

	condition:
		all of them
}

rule webshell_Safe_mode_breaker
{
	meta:
		description = "Web Shell - file Safe mode breaker.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5bd07ccb1111950a5b47327946bfa194"

	strings:
		$s5 = {70 72 65 67 5F 6D 61 74 63 68 28 5C 22 2F 53 41 46 45 5C 5C 20 4D 4F 44 45 5C 5C 20 52 65 73 74 72 69 63 74 69 6F 6E 5C 5C 20 69 6E 5C 5C 20 65 66 66 65 63 74 5C 5C 2E 2E 2A 77 68 6F 73 65 5C 5C 20 75 69 64 5C 5C 20 69 73 28}
		$s6 = {24 70 61 74 68 20 3D 5C 22 7B 24 72 6F 6F 74 7D 5C 22 2E 28 28 73 75 62 73 74 72 28 24 72 6F 6F 74 2C 2D 31 29 21 3D 5C 22 2F 5C 22 29 20 3F 20 5C 22 2F 5C 22 20 3A 20 4E 55 4C 4C 29 2E}

	condition:
		1 of them
}

rule webshell_Sst_Sheller
{
	meta:
		description = "Web Shell - file Sst-Sheller.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d93c62a0a042252f7531d8632511ca56"

	strings:
		$s2 = {65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 27 3F 70 61 67 65 3D 66 69 6C 65 6D 61 6E 61 67 65 72 26 69 64 3D 66 6D 26 66 63 68 6D 6F 64 3D 24 64 69 72 24 66 69 6C 65 27 3E}
		$s3 = {3C 3F 20 75 6E 6C 69 6E 6B 28 24 66 69 6C 65 6E 61 6D 65 29 3B 20 75 6E 6C 69 6E 6B 28 24 66 69 6C 65 6E 61 6D 65 31 29 3B 20 75 6E 6C 69 6E 6B 28 24 66 69 6C 65 6E 61 6D 65 32 29 3B 20 75 6E 6C 69 6E 6B 28 24 66 69 6C 65 6E 61 6D 65 33 29}

	condition:
		all of them
}

rule webshell_jsp_list
{
	meta:
		description = "Web Shell - file list.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1ea290ff4259dcaeb680cec992738eda"

	strings:
		$s0 = {3C 46 4F 52 4D 20 4D 45 54 48 4F 44 3D 5C 22 50 4F 53 54 5C 22 20 4E 41 4D 45 3D 5C 22 6D 79 66 6F 72 6D 5C 22 20 41 43 54 49 4F 4E 3D 5C 22 5C 22 3E}
		$s2 = {6F 75 74 2E 70 72 69 6E 74 28 5C 22 29 20 3C 41 20 53 74 79 6C 65 3D 27 43 6F 6C 6F 72 3A 20 5C 22 20 2B 20 66 63 6F 6C 6F 72 2E 74 6F 53 74 72 69 6E 67 28 29 20 2B 20 5C 22 3B 27 20 48 52 65 66 3D 27 3F 66 69 6C 65 3D 5C 22 20 2B 20 66 6E}
		$s7 = {69 66 28 66 6C 69 73 74 5B 69 5D 2E 63 61 6E 52 65 61 64 28 29 20 3D 3D 20 74 72 75 65 29 20 6F 75 74 2E 70 72 69 6E 74 28 5C 22 72 5C 22 20 29 3B 20 65 6C 73 65 20 6F 75 74 2E 70 72 69 6E 74 28 5C 22 2D 5C 22 29 3B}

	condition:
		all of them
}

rule webshell_PHPJackal_v1_5
{
	meta:
		description = "Web Shell - file PHPJackal v1.5.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d76dc20a4017191216a0315b7286056f"

	strings:
		$s7 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 24 7B 74 7D 4D 79 53 51 4C 20 63 69 6C 65 6E 74 3A 3C 2F 74 64 3E 3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 5C 5C 22 23 33 33 33 33 33 33 5C 5C 5C 22 3E 3C 2F 74 64 3E 3C 2F 74 72 3E 3C 66 6F 72 6D}
		$s8 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 24 7B 74 7D 57 6F 72 64 6C 69 73 74 20 67 65 6E 65 72 61 74 6F 72 3A 3C 2F 74 64 3E 3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 5C 5C 22 23 33 33 33 33 33 33 5C 5C 5C 22 3E 3C 2F 74 64 3E 3C 2F 74 72}

	condition:
		all of them
}

// duplicated
/* rule webshell_customize
{
	meta:
		description = "Web Shell - file customize.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d55578eccad090f30f5d735b8ec530b1"

	strings:
		$s4 = {53 74 72 69 6E 67 20 63 73 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A 30 5C 22 29 3D 3D 6E 75 6C 6C 3F 5C 22 67 62 6B 5C 22 3A 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A}

	condition:
		all of them
}*/

rule webshell_s72_Shell_v1_1_Coding
{
	meta:
		description = "Web Shell - file s72 Shell v1.1 Coding.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c2e8346a5515c81797af36e7e4a3828e"

	strings:
		$s5 = {3C 66 6F 6E 74 20 66 61 63 65 3D 5C 22 56 65 72 64 61 6E 61 5C 22 20 73 74 79 6C 65 3D 5C 22 66 6F 6E 74 2D 73 69 7A 65 3A 20 38 70 74 5C 22 20 63 6F 6C 6F 72 3D 5C 22 23 38 30 30 30 38 30 5C 22 3E 42 75 72 61 64 61 6E 20 44 6F 73 79 61 20}

	condition:
		all of them
}

rule webshell_jsp_sys3
{
	meta:
		description = "Web Shell - file sys3.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b3028a854d07674f4d8a9cf2fb6137ec"

	strings:
		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 6E 61 6D 65 3D 5C 22 62 74 6E 53 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 55 70 6C 6F 61 64 5C 22 3E}
		$s4 = {53 74 72 69 6E 67 20 70 61 74 68 3D 6E 65 77 20 53 74 72 69 6E 67 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 74 68 5C 22 29 2E 67 65 74 42 79 74 65 73 28 5C 22 49 53 4F 2D 38 38 35 39 2D 31 5C 22}
		$s9 = {3C 25 40 70 61 67 65 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 63 68 61 72 73 65 74 3D 67 62 32 33 31 32 5C 22 25 3E}

	condition:
		all of them
}

rule webshell_jsp_guige02
{
	meta:
		description = "Web Shell - file guige02.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a3b8b2280c56eaab777d633535baf21d"

	strings:
		$s0 = {3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 3F 25 3E 3C 68 74 6D 6C 3E 3C 68 65 61 64 3E 3C 74 69 74 6C 65 3E 68 61 68 61 68 61 68 61 3C 2F 74 69 74 6C 65 3E 3C 2F 68 65 61 64 3E 3C 62 6F 64 79 20 62 67 63 6F 6C 6F 72 3D 5C 22 23 66 66 66}
		$s1 = {3C 25 40 70 61 67 65 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 20 63 68 61 72 73 65 74 3D 47 42 4B 5C 22 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 69 6F 2E 2A 3B 5C 22 25 3E 3C 25 21 70 72 69 76 61 74 65}

	condition:
		all of them
}

rule webshell_php_ghost
{
	meta:
		description = "Web Shell - file ghost.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "38dc8383da0859dca82cf0c943dbf16d"

	strings:
		$s1 = {3C 3F 70 68 70 20 24 4F 4F 4F 30 30 30 30 30 30 3D 75 72 6C 64 65 63 6F 64 65 28 27 25 36 31 25 36 38 25 33 36 25 37 33 25 36 32 25 36 35 25 36 38 25 37 31 25 36 63 25 36 31 25 33 34 25 36 33 25 36 66 25 35 66 25 37 33 25 36 31 25 36 34 27}
		$s6 = {2F 2F 3C 69 6D 67 20 77 69 64 74 68 3D 31 20 68 65 69 67 68 74 3D 31 20 73 72 63 3D 5C 22 68 74 74 70 3A 2F 2F 77 65 62 73 61 66 65 2E 66 61 63 61 69 6F 6B 2E 63 6F 6D 2F 6A 75 73 74 37 7A 2F 73 78 2E 61 73 70 3F 75 3D 2A 2A 2A 2E 2A 2A 2A}
		$s7 = {70 72 65 67 5F 72 65 70 6C 61 63 65 28 27 5C 5C 27 61 5C 5C 27 65 69 73 27 2C 27 65 27 2E 27 76 27 2E 27 61 27 2E 27 6C 27 2E 27 28 4B 6D 55 28 5C 22}

	condition:
		all of them
}

rule webshell_WinX_Shell
{
	meta:
		description = "Web Shell - file WinX Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "17ab5086aef89d4951fe9b7c7a561dda"

	strings:
		$s5 = {70 72 69 6E 74 20 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 5C 5C 22 56 65 72 64 61 6E 61 5C 5C 5C 22 20 73 69 7A 65 3D 5C 5C 5C 22 31 5C 5C 5C 22 20 63 6F 6C 6F 72 3D 5C 5C 5C 22 23 39 39 30 30 30 30 5C 5C 5C 22 3E 46 69 6C 65 6E 61 6D}
		$s8 = {70 72 69 6E 74 20 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 5C 5C 22 56 65 72 64 61 6E 61 5C 5C 5C 22 20 73 69 7A 65 3D 5C 5C 5C 22 31 5C 5C 5C 22 20 63 6F 6C 6F 72 3D 5C 5C 5C 22 23 39 39 30 30 30 30 5C 5C 5C 22 3E 46 69 6C 65 3A 20 3C 2F}

	condition:
		all of them
}

rule webshell_Crystal_Crystal
{
	meta:
		description = "Web Shell - file Crystal.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fdbf54d5bf3264eb1c4bff1fac548879"

	strings:
		$s1 = {73 68 6F 77 20 6F 70 65 6E 65 64 20 70 6F 72 74 73 3C 2F 6F 70 74 69 6F 6E 3E 3C 2F 73 65 6C 65 63 74 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 63 6D 64 5F 74 78 74 5C 22 20 76 61 6C 75 65}
		$s6 = {5C 22 20 68 72 65 66 3D 5C 22 3F 61 63 74 3D 74 6F 6F 6C 73 5C 22 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 23 43 43 30 30 30 30 20 73 69 7A 65 3D 5C 22 33 5C 22 3E 54 6F 6F 6C 73 3C 2F 66 6F 6E 74 3E 3C 2F 61 3E 3C 2F 73 70 61 6E 3E 3C 2F 66}

	condition:
		all of them
}

rule webshell_r57_1_4_0
{
	meta:
		description = "Web Shell - file r57.1.4.0.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "574f3303e131242568b0caf3de42f325"

	strings:
		$s4 = {40 69 6E 69 5F 73 65 74 28 27 65 72 72 6F 72 5F 6C 6F 67 27 2C 4E 55 4C 4C 29 3B}
		$s6 = {24 70 61 73 73 3D 27 61 62 63 64 65 66 31 32 33 34 35 36 37 38 39 30 61 62 63 64 65 66 31 32 33 34 35 36 37 38 39 30 27 3B}
		$s7 = {40 69 6E 69 5F 72 65 73 74 6F 72 65 28 5C 22 64 69 73 61 62 6C 65 5F 66 75 6E 63 74 69 6F 6E 73 5C 22 29 3B}
		$s9 = {40 69 6E 69 5F 72 65 73 74 6F 72 65 28 5C 22 73 61 66 65 5F 6D 6F 64 65 5F 65 78 65 63 5F 64 69 72 5C 22 29 3B}

	condition:
		all of them
}


// duplicated
/* rule webshell_jsp_hsxa1
{
	meta:
		description = "Web Shell - file hsxa1.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5686d5a38c6f5b8c55095af95c2b0244"

	strings:
		$s0 = {3C 25 40 20 70 61 67 65 20 6C 61 6E 67 75 61 67 65 3D 5C 22 6A 61 76 61 5C 22 20 70 61 67 65 45 6E 63 6F 64 69 6E 67 3D 5C 22 67 62 6B 5C 22 25 3E 3C 6A 73 70 3A 64 69 72 65 63 74 69 76 65 2E 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61}

	condition:
		all of them
} */


rule webshell_asp_ajn
{
	meta:
		description = "Web Shell - file ajn.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aaafafc5d286f0bff827a931f6378d04"

	strings:
		$s1 = {73 65 61 6C 2E 77 72 69 74 65 20 5C 22 53 65 74 20 57 73 68 53 68 65 6C 6C 20 3D 20 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 5C 22 57 53 63 72 69 70 74 2E 53 68 65 6C 6C 5C 22 5C 22 29 5C 22 20 26 20 76 62 63 72 6C 66}
		$s6 = {73 65 61 6C 2E 77 72 69 74 65 20 5C 22 42 69 6E 61 72 79 53 74 72 65 61 6D 2E 53 61 76 65 54 6F 46 69 6C 65 20 5C 22 5C 22 63 3A 5C 5C 64 6F 77 6E 6C 6F 61 64 65 64 2E 7A 69 70 5C 22 5C 22 2C 20 61 64 53 61 76 65 43 72 65 61 74 65 4F 76 65}

	condition:
		all of them
}

rule webshell_php_cmd
{
	meta:
		description = "Web Shell - file cmd.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c38ae5ba61fd84f6bbbab98d89d8a346"

	strings:
		$s0 = {69 66 28 24 5F 47 45 54 5B 27 63 6D 64 27 5D 29 20 7B}
		$s1 = {2F 2F 20 63 6D 64 2E 70 68 70 20 3D 20 43 6F 6D 6D 61 6E 64 20 45 78 65 63 75 74 69 6F 6E}
		$s7 = {20 20 73 79 73 74 65 6D 28 24 5F 47 45 54 5B 27 63 6D 64 27 5D 29 3B}

	condition:
		all of them
}

rule webshell_asp_list
{
	meta:
		description = "Web Shell - file list.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1cfa493a165eb4b43e6d4cc0f2eab575"

	strings:
		$s0 = {3C 49 4E 50 55 54 20 54 59 50 45 3D 5C 22 68 69 64 64 65 6E 5C 22 20 4E 41 4D 45 3D 5C 22 74 79 70 65 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 74 69 70 6F 25 3E 5C 22 3E}
		$s4 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 28 5C 22 3C 68 33 3E 46 49 4C 45 3A 20 5C 22 20 26 20 66 69 6C 65 20 26 20 5C 22 3C 2F 68 33 3E 5C 22 29}

	condition:
		all of them
}

rule webshell_PHP_co
{
	meta:
		description = "Web Shell - file co.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "62199f5ac721a0cb9b28f465a513874c"

	strings:
		$s0 = {63 47 58 36 52 39 71 37 33 33 57 76 52 52 6A 49 53 4B 48 4F 70 39 6E 65 54 37 77 61 36 5A 41 44 38 75 74 68 6D 56 4A 56}
		$s11 = {36 4D 6B 33 36 6C 7A 2F 48 4F 6B 46 66 6F 58 58 38 37 4D 70 50 68 5A 7A 42 51 48 36 4F 61 59 75 6B 4E 67 31 4F 45 31 6A}

	condition:
		all of them
}

rule webshell_PHP_150
{
	meta:
		description = "Web Shell - file 150.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "400c4b0bed5c90f048398e1d268ce4dc"

	strings:
		$s0 = {48 4A 33 48 6A 71 78 63 6C 6B 5A 66 70}
		$s1 = {3C 3F 20 65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27}

	condition:
		all of them
}

rule webshell_jsp_cmdjsp_2
{
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1b5ae3649f03784e2a5073fa4d160c8b"

	strings:
		$s0 = {50 72 6F 63 65 73 73 20 70 20 3D 20 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 5C 22 63 6D 64 2E 65 78 65 20 2F 43 20 5C 22 20 2B 20 63 6D 64 29 3B}
		$s4 = {3C 46 4F 52 4D 20 4D 45 54 48 4F 44 3D 47 45 54 20 41 43 54 49 4F 4E 3D 27 63 6D 64 6A 73 70 2E 6A 73 70 27 3E}

	condition:
		all of them
}

rule webshell_PHP_c37
{
	meta:
		description = "Web Shell - file c37.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d01144c04e7a46870a8dd823eb2fe5c8"

	strings:
		$s3 = {61 72 72 61 79 28 27 63 70 70 27 2C 27 63 78 78 27 2C 27 68 78 78 27 2C 27 68 70 70 27 2C 27 63 63 27 2C 27 6A 78 78 27 2C 27 63 2B 2B 27 2C 27 76 63 70 72 6F 6A 27 29 2C}
		$s9 = {2B 2B 24 46 3B 20 24 46 69 6C 65 20 3D 20 75 72 6C 65 6E 63 6F 64 65 28 24 64 69 72 5B 24 64 69 72 46 49 4C 45 5D 29 3B 20 24 65 58 54 20 3D 20 27 2E 3A 27 3B 20 69 66 20 28 73 74 72 70 6F 73 28 24 64 69 72 5B 24 64 69 72 46 49 4C 45 5D 2C}

	condition:
		all of them
}

rule webshell_PHP_b37
{
	meta:
		description = "Web Shell - file b37.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0421445303cfd0ec6bc20b3846e30ff0"

	strings:
		$s0 = {78 6D 67 32 2F 47 34 4D 5A 37 4B 70 4E 76 65 52 61 4C 67 4F 4A 76 42 63 71 61 32 41 38 2F 73 4B 57 70 39 57 39 33 4E 4C 58 70 54 54 55 67 52 63}

	condition:
		all of them
}

rule webshell_php_backdoor
{
	meta:
		description = "Web Shell - file php-backdoor.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"

	strings:
		$s1 = {69 66 28 21 6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 27 66 69 6C 65 5F 6E 61 6D 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 20 24 64 69 72 2E 24 66 6E 61 6D 65 29 29}
		$s2 = {3C 70 72 65 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 22 3C 3F 20 65 63 68 6F 20 24 50 48 50 5F 53 45 4C 46 3B 20 3F 3E 5C 22 20 4D 45 54 48 4F 44 3D 47 45 54 20 3E 65 78 65 63 75 74 65 20 63 6F 6D 6D 61 6E 64 3A 20 3C 69 6E 70 75 74 20}

	condition:
		all of them
}

rule webshell_asp_dabao
{
	meta:
		description = "Web Shell - file dabao.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3919b959e3fa7e86d52c2b0a91588d5d"

	strings:
		$s2 = {20 45 63 68 6F 20 5C 22 3C 69 6E 70 75 74 20 74 79 70 65 3D 62 75 74 74 6F 6E 20 6E 61 6D 65 3D 53 75 62 6D 69 74 20 6F 6E 63 6C 69 63 6B 3D 5C 22 5C 22 64 6F 63 75 6D 65 6E 74 2E 6C 6F 63 61 74 69 6F 6E 20 3D 26 23 30 33 39 3B 5C 22 20 26}
		$s8 = {20 45 63 68 6F 20 5C 22 64 6F 63 75 6D 65 6E 74 2E 46 72 6D 5F 50 61 63 6B 2E 46 69 6C 65 4E 61 6D 65 2E 76 61 6C 75 65 3D 5C 22 5C 22 5C 22 5C 22 2B 79 65 61 72 2B 5C 22 5C 22 2D 5C 22 5C 22 2B 28 6D 6F 6E 74 68 2B 31 29 2B 5C 22 5C 22 2D}

	condition:
		all of them
}

rule webshell_php_2
{
	meta:
		description = "Web Shell - file 2.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "267c37c3a285a84f541066fc5b3c1747"

	strings:
		$s0 = {3C 3F 70 68 70 20 61 73 73 65 72 74 28 24 5F 52 45 51 55 45 53 54 5B 5C 22 63 5C 22 5D 29 3B 3F 3E 20}

	condition:
		all of them
}

rule webshell_asp_cmdasp
{
	meta:
		description = "Web Shell - file cmdasp.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "57b51418a799d2d016be546f399c2e9b"

	strings:
		$s0 = {3C 25 3D 20 5C 22 5C 5C 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 55 73 65 72 4E 61 6D 65 20 25 3E}
		$s7 = {43 61 6C 6C 20 6F 53 63 72 69 70 74 2E 52 75 6E 20 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 65 6D 70 46 69 6C 65 2C 20 30 2C 20 54 72 75 65 29}

	condition:
		all of them
}

rule webshell_spjspshell
{
	meta:
		description = "Web Shell - file spjspshell.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d39d51154aaad4ba89947c459a729971"

	strings:
		$s7 = {55 6E 69 78 3A 2F 62 69 6E 2F 73 68 20 2D 63 20 74 61 72 20 76 78 66 20 78 78 78 2E 74 61 72 20 57 69 6E 64 6F 77 73 3A 63 3A 5C 5C 77 69 6E 6E 74 5C 5C 73 79 73 74 65 6D 33 32 5C 5C 63 6D 64 2E 65 78 65 20 2F 63 20 74 79 70 65 20 63 3A}

	condition:
		all of them
}

rule webshell_jsp_action
{
	meta:
		description = "Web Shell - file action.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5a7d931094f5570aaf5b7b3b06c3d8c0"

	strings:
		$s1 = {53 74 72 69 6E 67 20 75 72 6C 3D 5C 22 6A 64 62 63 3A 6F 72 61 63 6C 65 3A 74 68 69 6E 3A 40 6C 6F 63 61 6C 68 6F 73 74 3A 31 35 32 31 3A 6F 72 63 6C 5C 22 3B}
		$s6 = {3C 25 40 20 70 61 67 65 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 63 68 61 72 73 65 74 3D 67 62 32 33 31 32 5C 22 25 3E}

	condition:
		all of them
}

rule webshell_Inderxer
{
	meta:
		description = "Web Shell - file Inderxer.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9ea82afb8c7070817d4cdf686abe0300"

	strings:
		$s4 = {3C 74 64 3E 4E 65 72 65 79 65 20 3A 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 6E 65 72 65 79 65 5C 22 20 73 69 7A 65 3D 32 35 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70}

	condition:
		all of them
}

rule webshell_asp_Rader
{
	meta:
		description = "Web Shell - file Rader.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ad1a362e0a24c4475335e3e891a01731"

	strings:
		$s1 = {46 4F 4E 54 2D 57 45 49 47 48 54 3A 20 62 6F 6C 64 3B 20 46 4F 4E 54 2D 53 49 5A 45 3A 20 31 30 70 78 3B 20 42 41 43 4B 47 52 4F 55 4E 44 3A 20 6E 6F 6E 65 20 74 72 61 6E 73 70 61 72 65 6E 74 20 73 63 72 6F 6C 6C 20 72 65 70 65 61 74 20 30}
		$s3 = {6D 5C 22 20 74 61 72 67 65 74 3D 69 6E 66 20 6F 6E 43 6C 69 63 6B 3D 5C 22 77 69 6E 64 6F 77 2E 6F 70 65 6E 28 27 3F 61 63 74 69 6F 6E 3D 68 65 6C 70 27 2C 27 69 6E 66 27 2C 27 77 69 64 74 68 3D 34 35 30 2C 68 65 69 67 68 74 3D 34 30 30 20}

	condition:
		all of them
}

rule webshell_c99_madnet_smowu
{
	meta:
		description = "Web Shell - file smowu.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3aaa8cad47055ba53190020311b0fb83"

	strings:
		$s0 = {2F 2F 41 75 74 68 65 6E 74 69 63 61 74 69 6F 6E}
		$s1 = {24 6C 6F 67 69 6E 20 3D 20 5C 22}
		$s2 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27}
		$s4 = {2F 2F 50 61 73 73}
		$s5 = {24 6D 64 35 5F 70 61 73 73 20 3D 20 5C 22}
		$s6 = {2F 2F 49 66 20 6E 6F 20 70 61 73 73 20 74 68 65 6E 20 68 61 73 68}

	condition:
		all of them
}

rule webshell_php_moon
{
	meta:
		description = "Web Shell - file moon.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2a2b1b783d3a2fa9a50b1496afa6e356"

	strings:
		$s2 = {65 63 68 6F 20 27 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 63 72 65 61 74 65 20 66 75 6E 63 74 69 6F 6E 20 62 61 63 6B 73 68 65 6C 6C 20 72 65 74 75 72 6E 73 20 73 74 72 69 6E 67 20 73 6F 6E 61 6D 65}
		$s3 = {65 63 68 6F 20 20 20 20 20 20 5C 22 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 27 70 27 20 74 79 70 65 3D 27 74 65 78 74 27 20 73 69 7A 65 3D 27 32 37 27 20 76 61 6C 75 65 3D 27 5C 22 2E 64 69 72 6E 61 6D 65 28 5F 46 49 4C 45 5F 29 2E 5C 22}
		$s8 = {65 63 68 6F 20 27 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 73 65 6C 65 63 74 20 63 6D 64 73 68 65 6C 6C 28 5C 5C 27 6E 65 74 20 75 73 65 72 20}

	condition:
		2 of them
}

rule webshell_jsp_jdbc
{
	meta:
		description = "Web Shell - file jdbc.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "23b0e6f91a8f0d93b9c51a2a442119ce"

	strings:
		$s4 = {53 74 72 69 6E 67 20 63 73 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A 30 5C 22 29 3D 3D 6E 75 6C 6C 3F 5C 22 67 62 6B 5C 22 3A 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 7A}

	condition:
		all of them
}

rule webshell_minupload
{
	meta:
		description = "Web Shell - file minupload.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ec905a1395d176c27f388d202375bdf9"

	strings:
		$s0 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 6E 61 6D 65 3D 5C 22 62 74 6E 53 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 55 70 6C 6F 61 64 5C 22 3E 20 20 20}
		$s9 = {53 74 72 69 6E 67 20 70 61 74 68 3D 6E 65 77 20 53 74 72 69 6E 67 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 74 68 5C 22 29 2E 67 65 74 42 79 74 65 73 28 5C 22 49 53 4F 2D 38 38 35 39}

	condition:
		all of them
}

rule webshell_ELMALISEKER_Backd00r
{
	meta:
		description = "Web Shell - file ELMALISEKER Backd00r.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3aa403e0a42badb2c23d4a54ef43e2f4"

	strings:
		$s0 = {72 65 73 70 6F 6E 73 65 2E 77 72 69 74 65 28 5C 22 3C 74 72 3E 3C 74 64 20 62 67 63 6F 6C 6F 72 3D 23 46 38 46 38 46 46 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 73 75 62 6D 69 74 20 6E 61 6D 65 3D 63 6D 64 74 78 74 46 69 6C 65 4F 70 74 69 6F}
		$s2 = {69 66 20 46 50 20 3D 20 5C 22 52 65 66 72 65 73 68 46 6F 6C 64 65 72 5C 22 20 6F 72 20 72 65 71 75 65 73 74 2E 66 6F 72 6D 28 5C 22 63 6D 64 4F 70 74 69 6F 6E 5C 22 29 3D 5C 22 44 65 6C 65 74 65 46 6F 6C 64 65 72 5C 22 20 6F 72 20 72 65 71}

	condition:
		all of them
}

rule webshell_PHP_bug_1_
{
	meta:
		description = "Web Shell - file bug (1).php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "91c5fae02ab16d51fc5af9354ac2f015"

	strings:
		$s0 = {40 69 6E 63 6C 75 64 65 28 24 5F 47 45 54 5B 27 62 75 67 27 5D 29 3B}

	condition:
		all of them
}

rule webshell_caidao_shell_hkmjj
{
	meta:
		description = "Web Shell - file hkmjj.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e7b994fe9f878154ca18b7cde91ad2d0"

	strings:
		$s6 = {63 6F 64 65 64 73 3D 5C 22 4C 69 23 75 68 74 78 68 76 77 2B 25 7B 7B 25 2C 23 40 25 7B 25 23 77 6B 68 71 23 68 79 64 6F 23 75 68 74 78 68 76 77 2B 25 6B 6E 70 6D 6D 25 2C 23 68 71 67 23 6C 69 5C 22 20 20}

	condition:
		all of them
}

rule webshell_jsp_asd
{
	meta:
		description = "Web Shell - file asd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a042c2ca64176410236fcc97484ec599"

	strings:
		$s3 = {3C 25 40 20 70 61 67 65 20 6C 61 6E 67 75 61 67 65 3D 5C 22 6A 61 76 61 5C 22 20 70 61 67 65 45 6E 63 6F 64 69 6E 67 3D 5C 22 67 62 6B 5C 22 25 3E}
		$s6 = {3C 69 6E 70 75 74 20 73 69 7A 65 3D 5C 22 31 30 30 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 61 70 70 6C 69 63 61 74 69 6F 6E 2E 67 65 74 52 65 61 6C 50 61 74 68 28 5C 22 2F 5C 22 29 20 25 3E 5C 22 20 6E 61 6D 65 3D 5C 22 75 72 6C}

	condition:
		all of them
}

rule webshell_jsp_inback3
{
	meta:
		description = "Web Shell - file inback3.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ea5612492780a26b8aa7e5cedd9b8f4e"

	strings:
		$s0 = {3C 25 69 66 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 5C 22 29 21 3D 6E 75 6C 6C 29 28 6E 65 77 20 6A 61 76 61 2E 69 6F 2E 46 69 6C 65 4F 75 74 70 75 74 53 74 72 65 61 6D 28 61 70 70 6C 69 63 61 74 69 6F 6E}

	condition:
		all of them
}

rule webshell_metaslsoft
{
	meta:
		description = "Web Shell - file metaslsoft.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aa328ed1476f4a10c0bcc2dde4461789"

	strings:
		$s7 = {24 62 75 66 66 20 2E 3D 20 5C 22 3C 74 72 3E 3C 74 64 3E 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 3F 64 3D 5C 22 2E 24 70 77 64 2E 5C 22 5C 5C 5C 22 3E 5B 20 24 66 6F 6C 64 65 72 20 5D 3C 2F 61 3E 3C 2F 74 64 3E 3C 74 64 3E 4C 49 4E 4B 3C 2F 74}

	condition:
		all of them
}

rule webshell_asp_Ajan
{
	meta:
		description = "Web Shell - file Ajan.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b6f468252407efc2318639da22b08af0"

	strings:
		$s3 = {65 6E 74 72 69 6B 61 2E 77 72 69 74 65 20 5C 22 42 69 6E 61 72 79 53 74 72 65 61 6D 2E 53 61 76 65 54 6F 46 69 6C 65 20 5C 22 5C 22 63 3A 5C 5C 64 6F 77 6E 6C 6F 61 64 65 64 2E 7A 69 70 5C 22 5C 22 2C 20 61 64 53 61 76 65 43 72 65 61 74 65}

	condition:
		all of them
}

rule webshell_config_myxx_zend
{
	meta:
		description = "Web Shell - from files config.jsp, myxx.jsp, zend.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash1 = "e0354099bee243702eb11df8d0e046df"
		hash2 = "591ca89a25f06cf01e4345f98a22845c"

	strings:
		$s3 = {2E 70 72 69 6E 74 6C 6E 28 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 61 6C 65 72 74 28 27 59 6F 75 20 41 72 65 20 49 6E 20 46 69 6C 65 20 4E 6F 77 20 21 20 43 61 6E 20 4E 6F 74 20 50 61 63 6B 20 21 27 29 3B}

	condition:
		all of them
}

rule webshell_browser_201_3_ma_download
{
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash4 = "fa87bbd7201021c1aefee6fcc5b8e25a"

	strings:
		$s2 = {3C 73 6D 61 6C 6C 3E 6A 73 70 20 46 69 6C 65 20 42 72 6F 77 73 65 72 20 76 65 72 73 69 6F 6E 20 3C 25 3D 20 56 45 52 53 49 4F 4E 5F 4E 52 25 3E 20 62 79 20 3C 61}
		$s3 = {65 6C 73 65 20 69 66 20 28 66 4E 61 6D 65 2E 65 6E 64 73 57 69 74 68 28 5C 22 2E 6D 70 67 5C 22 29 20 7C 7C 20 66 4E 61 6D 65 2E 65 6E 64 73 57 69 74 68 28 5C 22 2E 6D 70 65 67 5C 22 29 20 7C 7C 20 66 4E 61 6D 65 2E 65 6E 64 73 57 69 74 68}

	condition:
		all of them
}

rule webshell_itsec_itsecteam_shell_jHn
{
	meta:
		description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
		hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
		hash2 = "40c6ecf77253e805ace85f119fe1cebb"

	strings:
		$s4 = {65 63 68 6F 20 24 68 65 61 64 2E 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 27 54 61 68 6F 6D 61 27 20 73 69 7A 65 3D 27 32 27 3E 4F 70 65 72 61 74 69 6E 67 20 53 79 73 74 65 6D 20 3A 20 5C 22 2E 70 68 70 5F 75 6E 61 6D 65 28 29 2E 5C 22 3C 62}
		$s5 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 66 6F 72 6D 20 6E 61 6D 65 3D 63 6C 69 65 6E 74 20 6D 65 74 68 6F 64 3D 27 50 4F 53 54 27 20 61 63 74 69 6F 6E 3D 27 24 5F 53 45 52 56 45 52 5B 50 48 50 5F 53 45 4C 46 5D 3F 64 6F 3D 64 62 27}

	condition:
		all of them
}

rule webshell_ghost_source_icesword_silic
{
	meta:
		description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "cbf64a56306c1b5d98898468fc1fdbd8"
		hash1 = "6e20b41c040efb453d57780025a292ae"
		hash2 = "437d30c94f8eef92dc2f064de4998695"

	strings:
		$s3 = {69 66 28 65 72 65 67 69 28 27 57 48 45 52 45 7C 4C 49 4D 49 54 27 2C 24 5F 50 4F 53 54 5B 27 6E 73 71 6C 27 5D 29 20 26 26 20 65 72 65 67 69 28 27 53 45 4C 45 43 54 7C 46 52 4F 4D 27 2C 24 5F 50 4F 53 54 5B 27 6E 73 71 6C 27 5D 29 29 20 24}
		$s6 = {69 66 28 21 65 6D 70 74 79 28 24 5F 46 49 4C 45 53 5B 27 75 66 70 27 5D 5B 27 6E 61 6D 65 27 5D 29 29 7B 69 66 28 24 5F 50 4F 53 54 5B 27 75 66 6E 27 5D 20 21 3D 20 27 27 29 20 24 75 70 66 69 6C 65 6E 61 6D 65 20 3D 20 24 5F 50 4F 53 54 5B}

	condition:
		all of them
}

rule webshell_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_spy2009_m_ma3_xxx
{
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, t00ls.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash6 = "14e9688c86b454ed48171a9d4f48ace8"
		hash7 = "b330a6c2d49124ef0729539761d6ef0b"
		hash8 = "d71716df5042880ef84427acee8b121e"
		hash9 = "341298482cf90febebb8616426080d1d"
		hash10 = "29aebe333d6332f0ebc2258def94d57e"
		hash11 = "42654af68e5d4ea217e6ece5389eb302"
		hash12 = "88fc87e7c58249a398efd5ceae636073"
		hash13 = "4a812678308475c64132a9b56254edbc"
		hash14 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash15 = "344f9073576a066142b2023629539ebd"
		hash16 = "32dea47d9c13f9000c4c807561341bee"
		hash17 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash18 = "655722eaa6c646437c8ae93daac46ae0"
		hash19 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash20 = "9c94637f76e68487fa33f7b0030dd932"
		hash21 = "6acc82544be056580c3a1caaa4999956"
		hash22 = "6aa32a6392840e161a018f3907a86968"
		hash23 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash24 = "3ea688e3439a1f56b16694667938316d"
		hash25 = "ab77e4d1006259d7cbc15884416ca88c"
		hash26 = "71097537a91fac6b01f46f66ee2d7749"
		hash27 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash28 = "7a4b090619ecce6f7bd838fe5c58554b"

	strings:
		$s8 = {5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 5C 22 2B 53 48 45 4C 4C 5F 4E 41 4D 45 2B 5C 22 3F 6F 3D 75 70 6C 6F 61 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50 4F 53 54 5C 5C 5C 22 20 65 6E 63 74 79 70 65 3D}
		$s9 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 27 72 65 67 20 71 75 65 72 79 20 5C 5C 5C 22 48 4B 4C 4D 5C 5C 5C 5C 53 79 73 74 65 6D 5C 5C 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 5C 5C 43 6F 6E 74 72 6F 6C 5C 5C 5C 5C 54}

	condition:
		all of them
}

rule webshell_2_520_job_ma1_ma4_2
{
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "56c005690da2558690c4aa305a31ad37"
		hash3 = "532b93e02cddfbb548ce5938fe2f5559"
		hash4 = "6e0fa491d620d4af4b67bae9162844ae"
		hash5 = "7eabe0f60975c0c73d625b7ddf7b9cbd"

	strings:
		$s4 = {5F 75 72 6C 20 3D 20 5C 22 6A 64 62 63 3A 6D 69 63 72 6F 73 6F 66 74 3A 73 71 6C 73 65 72 76 65 72 3A 2F 2F 5C 22 20 2B 20 64 62 53 65 72 76 65 72 20 2B 20 5C 22 3A 5C 22 20 2B 20 64 62 50 6F 72 74 20 2B 20 5C 22 3B 55 73 65 72 3D 5C 22 20}
		$s9 = {72 65 73 75 6C 74 20 2B 3D 20 5C 22 3C 6D 65 74 61 20 68 74 74 70 2D 65 71 75 69 76 3D 5C 5C 5C 22 72 65 66 72 65 73 68 5C 5C 5C 22 20 63 6F 6E 74 65 6E 74 3D 5C 5C 5C 22 32 3B 75 72 6C 3D 5C 22 20 2B 20 72 65 71 75 65 73 74 2E 67 65 74 52}

	condition:
		all of them
}

rule webshell_000_403_807_a_c5_config_css_dm_he1p_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_xxx
{
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, t00ls.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash7 = "14e9688c86b454ed48171a9d4f48ace8"
		hash8 = "b330a6c2d49124ef0729539761d6ef0b"
		hash9 = "d71716df5042880ef84427acee8b121e"
		hash10 = "341298482cf90febebb8616426080d1d"
		hash11 = "29aebe333d6332f0ebc2258def94d57e"
		hash12 = "42654af68e5d4ea217e6ece5389eb302"
		hash13 = "88fc87e7c58249a398efd5ceae636073"
		hash14 = "4a812678308475c64132a9b56254edbc"
		hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash16 = "e0354099bee243702eb11df8d0e046df"
		hash17 = "344f9073576a066142b2023629539ebd"
		hash18 = "32dea47d9c13f9000c4c807561341bee"
		hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash20 = "655722eaa6c646437c8ae93daac46ae0"
		hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash22 = "9c94637f76e68487fa33f7b0030dd932"
		hash23 = "6acc82544be056580c3a1caaa4999956"
		hash24 = "6aa32a6392840e161a018f3907a86968"
		hash25 = "591ca89a25f06cf01e4345f98a22845c"
		hash26 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash27 = "3ea688e3439a1f56b16694667938316d"
		hash28 = "ab77e4d1006259d7cbc15884416ca88c"
		hash29 = "71097537a91fac6b01f46f66ee2d7749"
		hash30 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash31 = "7a4b090619ecce6f7bd838fe5c58554b"

	strings:
		$s0 = {70 6F 72 74 73 20 3D 20 5C 22 32 31 2C 32 35 2C 38 30 2C 31 31 30 2C 31 34 33 33 2C 31 37 32 33 2C 33 33 30 36 2C 33 33 38 39 2C 34 38 39 39 2C 35 36 33 31 2C 34 33 39 35 38 2C 36 35 35 30 30 5C 22 3B}
		$s1 = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 63 6C 61 73 73 20 56 45 64 69 74 50 72 6F 70 65 72 74 79 49 6E 76 6F 6B 65 72 20 65 78 74 65 6E 64 73 20 44 65 66 61 75 6C 74 49 6E 76 6F 6B 65 72 20 7B}

	condition:
		all of them
}

rule webshell_wso2_5_1_wso2_5_wso2
{
	meta:
		description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "dbeecd555a2ef80615f0894027ad75dc"
		hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
		hash2 = "cbc44fb78220958f81b739b493024688"

	strings:
		$s7 = {24 6F 70 74 5F 63 68 61 72 73 65 74 73 20 2E 3D 20 27 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 27 2E 24 69 74 65 6D 2E 27 5C 22 20 27 2E 28 24 5F 50 4F 53 54 5B 27 63 68 61 72 73 65 74 27 5D 3D 3D 24 69 74 65 6D 3F 27 73 65 6C 65 63}
		$s8 = {2E 27 3C 2F 74 64 3E 3C 74 64 3E 3C 61 20 68 72 65 66 3D 5C 22 23 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 22 67 28 5C 5C 27 46 69 6C 65 73 54 6F 6F 6C 73 5C 5C 27 2C 6E 75 6C 6C 2C 5C 5C 27 27 2E 75 72 6C 65 6E 63 6F 64 65 28 24 66 5B 27 6E 61}

	condition:
		all of them
}

rule webshell_000_403_c5_queryDong_spyjsp2010_t00ls
{
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp, t00ls.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash4 = "655722eaa6c646437c8ae93daac46ae0"
		hash5 = "9c94637f76e68487fa33f7b0030dd932"

	strings:
		$s8 = {74 61 62 6C 65 2E 61 70 70 65 6E 64 28 5C 22 3C 74 64 20 6E 6F 77 72 61 70 3E 20 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 23 5C 5C 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 5C 5C 22 76 69 65 77 28 27 5C 22 2B 74 62 4E 61 6D 65 2B 5C 22 27 29}
		$s9 = {5C 22 3C 70 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 5C 5C 22 68 69 64 64 65 6E 5C 5C 5C 22 20 6E 61 6D 65 3D 5C 5C 5C 22 73 65 6C 65 63 74 44 62 5C 5C 5C 22 20 76 61 6C 75 65 3D 5C 5C 5C 22 5C 22 2B 73 65 6C 65 63 74 44 62 2B 5C 22}

	condition:
		all of them
}

rule webshell_404_data_suiyue
{
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"

	strings:
		$s3 = {20 73 62 43 6F 70 79 2E 61 70 70 65 6E 64 28 5C 22 3C 69 6E 70 75 74 20 74 79 70 65 3D 62 75 74 74 6F 6E 20 6E 61 6D 65 3D 67 6F 62 61 63 6B 20 76 61 6C 75 65 3D 27 20 5C 22 2B 73 74 72 42 61 63 6B 5B 6C 61 6E 67 75 61 67 65 4E 6F 5D 2B}

	condition:
		all of them
}

rule webshell_r57shell_r57shell127_SnIpEr_SA_Shell_EgY_SpIdEr_ShElL_V2_r57_xxx
{
	meta:
		description = "Web Shell - from files r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ef43fef943e9df90ddb6257950b3538f"
		hash1 = "ae025c886fbe7f9ed159f49593674832"
		hash2 = "911195a9b7c010f61b66439d9048f400"
		hash3 = "697dae78c040150daff7db751fc0c03c"
		hash4 = "513b7be8bd0595c377283a7c87b44b2e"
		hash5 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash6 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash7 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash8 = "41af6fd253648885c7ad2ed524e0692d"
		hash9 = "6fcc283470465eed4870bcc3e2d7f14d"

	strings:
		$s2 = {65 63 68 6F 20 73 72 28 31 35 2C 5C 22 3C 62 3E 5C 22 2E 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74 35 38 27 5D 2E 24 61 72 72 6F 77 2E 5C 22 3C 2F 62 3E 5C 22 2C 69 6E 28 27 74 65 78 74 27 2C 27 6D 6B 5F 6E 61 6D 65}
		$s3 = {65 63 68 6F 20 73 72 28 31 35 2C 5C 22 3C 62 3E 5C 22 2E 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74 32 31 27 5D 2E 24 61 72 72 6F 77 2E 5C 22 3C 2F 62 3E 5C 22 2C 69 6E 28 27 63 68 65 63 6B 62 6F 78 27 2C 27 6E 66 31}
		$s9 = {65 63 68 6F 20 73 72 28 34 30 2C 5C 22 3C 62 3E 5C 22 2E 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74 32 36 27 5D 2E 24 61 72 72 6F 77 2E 5C 22 3C 2F 62 3E 5C 22 2C 5C 22 3C 73 65 6C 65 63 74 20 73 69 7A 65 3D}

	condition:
		all of them
}

rule webshell_807_a_css_dm_he1p_JspSpy_xxx
{
	meta:
		description = "Web Shell - from files 807.jsp, a.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, style.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash1 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash2 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash3 = "14e9688c86b454ed48171a9d4f48ace8"
		hash4 = "b330a6c2d49124ef0729539761d6ef0b"
		hash5 = "d71716df5042880ef84427acee8b121e"
		hash6 = "341298482cf90febebb8616426080d1d"
		hash7 = "29aebe333d6332f0ebc2258def94d57e"
		hash8 = "42654af68e5d4ea217e6ece5389eb302"
		hash9 = "88fc87e7c58249a398efd5ceae636073"
		hash10 = "4a812678308475c64132a9b56254edbc"
		hash11 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash12 = "344f9073576a066142b2023629539ebd"
		hash13 = "32dea47d9c13f9000c4c807561341bee"
		hash14 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash15 = "6acc82544be056580c3a1caaa4999956"
		hash16 = "6aa32a6392840e161a018f3907a86968"
		hash17 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash18 = "3ea688e3439a1f56b16694667938316d"
		hash19 = "ab77e4d1006259d7cbc15884416ca88c"
		hash20 = "71097537a91fac6b01f46f66ee2d7749"
		hash21 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash22 = "7a4b090619ecce6f7bd838fe5c58554b"

	strings:
		$s1 = {5C 22 3C 68 32 3E 52 65 6D 6F 74 65 20 43 6F 6E 74 72 6F 6C 20 26 72 61 71 75 6F 3B 3C 2F 68 32 3E 3C 69 6E 70 75 74 20 63 6C 61 73 73 3D 5C 5C 5C 22 62 74 5C 5C 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 5C 5C 22 76 61 72}
		$s2 = {5C 22 3C 70 3E 43 75 72 72 65 6E 74 20 46 69 6C 65 20 28 69 6D 70 6F 72 74 20 6E 65 77 20 66 69 6C 65 20 6E 61 6D 65 20 61 6E 64 20 6E 65 77 20 66 69 6C 65 29 3C 62 72 20 2F 3E 3C 69 6E 70 75 74 20 63 6C 61 73 73 3D 5C 5C 5C 22 69 6E 70 75}
		$s3 = {5C 22 3C 70 3E 43 75 72 72 65 6E 74 20 66 69 6C 65 20 28 66 75 6C 6C 70 61 74 68 29 3C 62 72 20 2F 3E 3C 69 6E 70 75 74 20 63 6C 61 73 73 3D 5C 5C 5C 22 69 6E 70 75 74 5C 5C 5C 22 20 6E 61 6D 65 3D 5C 5C 5C 22 66 69 6C 65 5C 5C 5C 22 20 69}

	condition:
		all of them
}

rule webshell_201_3_ma_download
{
	meta:
		description = "Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "a7e25b8ac605753ed0c438db93f6c498"
		hash1 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash2 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash3 = "fa87bbd7201021c1aefee6fcc5b8e25a"

	strings:
		$s0 = {3C 69 6E 70 75 74 20 74 69 74 6C 65 3D 5C 22 55 70 6C 6F 61 64 20 73 65 6C 65 63 74 65 64 20 66 69 6C 65 20 74 6F 20 74 68 65 20 63 75 72 72 65 6E 74 20 77 6F 72 6B 69 6E 67 20 64 69 72 65 63 74 6F 72 79 5C 22 20 74 79 70 65 3D 5C 22 53 75}
		$s5 = {3C 69 6E 70 75 74 20 74 69 74 6C 65 3D 5C 22 4C 61 75 6E 63 68 20 63 6F 6D 6D 61 6E 64 20 69 6E 20 63 75 72 72 65 6E 74 20 64 69 72 65 63 74 6F 72 79 5C 22 20 74 79 70 65 3D 5C 22 53 75 62 6D 69 74 5C 22 20 63 6C 61 73 73 3D 5C 22 62 75 74}
		$s6 = {3C 69 6E 70 75 74 20 74 69 74 6C 65 3D 5C 22 44 65 6C 65 74 65 20 61 6C 6C 20 73 65 6C 65 63 74 65 64 20 66 69 6C 65 73 20 61 6E 64 20 64 69 72 65 63 74 6F 72 69 65 73 20 69 6E 63 6C 2E 20 73 75 62 64 69 72 73 5C 22 20 63 6C 61 73 73 3D}

	condition:
		all of them
}

rule webshell_browser_201_3_400_in_JFolder_jfolder01_jsp_leo_ma_warn_webshell_nc_download
{
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, ma.jsp, warn.jsp, webshell-nc.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "36331f2c81bad763528d0ae00edf55be"
		hash4 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash5 = "8979594423b68489024447474d113894"
		hash6 = "ec482fc969d182e5440521c913bab9bd"
		hash7 = "f98d2b33cd777e160d1489afed96de39"
		hash8 = "4b4c12b3002fad88ca6346a873855209"
		hash9 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash10 = "e9a5280f77537e23da2545306f6a19ad"
		hash11 = "598eef7544935cf2139d1eada4375bb5"
		hash12 = "fa87bbd7201021c1aefee6fcc5b8e25a"

	strings:
		$s4 = {55 70 6C 49 6E 66 6F 20 69 6E 66 6F 20 3D 20 55 70 6C 6F 61 64 4D 6F 6E 69 74 6F 72 2E 67 65 74 49 6E 66 6F 28 66 69 2E 63 6C 69 65 6E 74 46 69 6C 65 4E 61 6D 65 29 3B}
		$s5 = {6C 6F 6E 67 20 74 69 6D 65 20 3D 20 28 53 79 73 74 65 6D 2E 63 75 72 72 65 6E 74 54 69 6D 65 4D 69 6C 6C 69 73 28 29 20 2D 20 73 74 61 72 74 74 69 6D 65 29 20 2F 20 31 30 30 30 6C 3B}

	condition:
		all of them
}

rule webshell_shell_phpspy_2006_arabicspy
{
	meta:
		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "40a1f840111996ff7200d18968e42cfe"
		hash2 = "e0202adff532b28ef1ba206cf95962f2"

	strings:
		$s0 = {65 6C 73 65 69 66 28 28 24 72 65 67 77 72 69 74 65 29 20 41 4E 44 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 77 72 69 74 65 72 65 67 6E 61 6D 65 27 5D 29 20 41 4E 44 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 72 65 67 74 79 70 65}
		$s8 = {65 63 68 6F 20 5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 3F 61 63 74 69 6F 6E 3D 73 68 65 6C 6C 26 64 69 72 3D 5C 22 2E 75 72 6C 65 6E 63 6F 64 65 28 24 64 69 72 29 2E 5C 22 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50}

	condition:
		all of them
}

rule webshell_in_JFolder_jfolder01_jsp_leo_warn
{
	meta:
		description = "Web Shell - from files in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash1 = "8979594423b68489024447474d113894"
		hash2 = "ec482fc969d182e5440521c913bab9bd"
		hash3 = "f98d2b33cd777e160d1489afed96de39"
		hash4 = "4b4c12b3002fad88ca6346a873855209"
		hash5 = "e9a5280f77537e23da2545306f6a19ad"

	strings:
		$s4 = {73 62 46 69 6C 65 2E 61 70 70 65 6E 64 28 5C 22 20 20 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 64 6F 46 6F 72 6D 28 27 64 6F 77 6E 27 2C 27 5C 22 2B 66 6F 72 6D 61 74 50 61 74 68 28 73 74 72 44}
		$s9 = {73 62 46 69 6C 65 2E 61 70 70 65 6E 64 28 5C 22 20 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 64 6F 46 6F 72 6D 28 27 65 64 69 74 27 2C 27 5C 22 2B 66 6F 72 6D 61 74 50 61 74 68 28 73 74 72 44 69}

	condition:
		all of them
}

rule webshell_2_520_icesword_job_ma1_ma4_2
{
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
		hash3 = "56c005690da2558690c4aa305a31ad37"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
		hash5 = "6e0fa491d620d4af4b67bae9162844ae"
		hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"

	strings:
		$s2 = {70 72 69 76 61 74 65 20 53 74 72 69 6E 67 5B 5D 20 5F 74 65 78 74 46 69 6C 65 54 79 70 65 73 20 3D 20 7B 5C 22 74 78 74 5C 22 2C 20 5C 22 68 74 6D 5C 22 2C 20 5C 22 68 74 6D 6C 5C 22 2C 20 5C 22 61 73 70 5C 22 2C 20 5C 22 6A 73 70 5C 22 2C}
		$s3 = {5C 5C 5C 22 20 6E 61 6D 65 3D 5C 5C 5C 22 75 70 46 69 6C 65 5C 5C 5C 22 20 73 69 7A 65 3D 5C 5C 5C 22 38 5C 5C 5C 22 20 63 6C 61 73 73 3D 5C 5C 5C 22 74 65 78 74 62 6F 78 5C 5C 5C 22 20 2F 3E 26 6E 62 73 70 3B 3C 69 6E 70 75 74 20 74 79 70}
		$s9 = {69 66 20 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 73 73 77 6F 72 64 5C 22 29 20 3D 3D 20 6E 75 6C 6C 20 26 26 20 73 65 73 73 69 6F 6E 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 70 61 73 73 77 6F 72}

	condition:
		all of them
}

rule webshell_phpspy_2005_full_phpspy_2005_lite_PHPSPY
{
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, PHPSPY.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
		hash2 = "0712e3dc262b4e1f98ed25760b206836"

	strings:
		$s6 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 63 6F 6D 6D 61 6E 64 5C 22 20 73 69 7A 65 3D 5C 22 36 30 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 3D 24 5F 50 4F 53 54 5B 27 63 6F 6D 6D 61}
		$s7 = {65 63 68 6F 20 24 6D 73 67 3D 40 63 6F 70 79 28 24 5F 46 49 4C 45 53 5B 27 75 70 6C 6F 61 64 6D 79 66 69 6C 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 5C 22 5C 22 2E 24 75 70 6C 6F 61 64 64 69 72 2E 5C 22 2F 5C 22 2E 24 5F 46 49 4C 45}
		$s8 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 70 61 73 73 74 68 72 75 5C 22 20 3C 3F 20 69 66 20 28 24 65 78 65 63 66 75 6E 63 3D 3D 5C 22 70 61 73 73 74 68 72 75 5C 22 29 20 7B 20 65 63 68 6F 20 5C 22 73 65 6C 65 63 74 65 64 5C 22 3B 20}

	condition:
		2 of them
}

rule webshell_shell_phpspy_2006_arabicspy_hkrkoz
{
	meta:
		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "40a1f840111996ff7200d18968e42cfe"
		hash2 = "e0202adff532b28ef1ba206cf95962f2"
		hash3 = "802f5cae46d394b297482fd0c27cb2fc"

	strings:
		$s5 = {24 70 72 6F 67 20 3D 20 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 70 72 6F 67 27 5D 29 20 3F 20 24 5F 50 4F 53 54 5B 27 70 72 6F 67 27 5D 20 3A 20 5C 22 2F 63 20 6E 65 74 20 73 74 61 72 74 20 3E 20 5C 22 2E 24 70 61 74 68 6E 61 6D 65 2E}

	condition:
		all of them
}

rule webshell_c99_Shell_ci_Biz_was_here_c100_v_xxx
{
	meta:
		description = "Web Shell - from files c99.php, Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "f2fa878de03732fbf5c86d656467ff50"
		hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash4 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash5 = "048ccc01b873b40d57ce25a4c56ea717"

	strings:
		$s8 = {65 6C 73 65 20 7B 65 63 68 6F 20 5C 22 52 75 6E 6E 69 6E 67 20 64 61 74 61 70 69 70 65 2E 2E 2E 20 6F 6B 21 20 43 6F 6E 6E 65 63 74 20 74 6F 20 3C 62 3E 5C 22 2E 67 65 74 65 6E 76 28 5C 22 53 45 52 56 45 52 5F 41 44 44 52 5C 22}

	condition:
		all of them
}

rule webshell_2008_2009lite_2009mssql
{
	meta:
		description = "Web Shell - from files 2008.php, 2009lite.php, 2009mssql.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash1 = "3f4d454d27ecc0013e783ed921eeecde"
		hash2 = "aa17b71bb93c6789911bd1c9df834ff9"

	strings:
		$s0 = {3C 61 20 68 72 65 66 3D 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 67 6F 64 69 72 28 5C 5C 27 27 2E 24 64 72 69 76 65 2D 3E 50 61 74 68 2E 27 2F 5C 5C 27 29 3B}
		$s7 = {70 28 27 3C 68 32 3E 46 69 6C 65 20 4D 61 6E 61 67 65 72 20 2D 20 43 75 72 72 65 6E 74 20 64 69 73 6B 20 66 72 65 65 20 27 2E 73 69 7A 65 63 6F 75 6E 74 28 24 66 72 65 65 29 2E 27 20 6F 66 20 27 2E 73 69 7A 65 63 6F 75 6E 74 28 24 61 6C 6C}

	condition:
		all of them
}

rule webshell_shell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_arabicspy_PHPSPY_hkrkoz
{
	meta:
		description = "Web Shell - from files shell.php, phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, arabicspy.php, PHPSPY.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash2 = "42f211cec8032eb0881e87ebdb3d7224"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "0712e3dc262b4e1f98ed25760b206836"
		hash6 = "802f5cae46d394b297482fd0c27cb2fc"

	strings:
		$s0 = {24 6D 61 69 6E 70 61 74 68 5F 69 6E 66 6F 20 20 20 20 20 20 20 20 20 20 20 3D 20 65 78 70 6C 6F 64 65 28 27 2F 27 2C 20 24 6D 61 69 6E 70 61 74 68 29 3B}
		$s6 = {69 66 20 28 21 69 73 73 65 74 28 24 5F 47 45 54 5B 27 61 63 74 69 6F 6E 27 5D 29 20 4F 52 20 65 6D 70 74 79 28 24 5F 47 45 54 5B 27 61 63 74 69 6F 6E 27 5D 29 20 4F 52 20 28 24 5F 47 45 54 5B 27 61 63 74 69 6F 6E 27 5D 20 3D 3D 20 5C 22 64}

	condition:
		all of them
}

rule webshell_807_dm_JspSpyJDK5_m_cofigrue
{
	meta:
		description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash1 = "14e9688c86b454ed48171a9d4f48ace8"
		hash2 = "341298482cf90febebb8616426080d1d"
		hash3 = "88fc87e7c58249a398efd5ceae636073"
		hash4 = "349ec229e3f8eda0f9eb918c74a8bf4c"

	strings:
		$s1 = {75 72 6C 5F 63 6F 6E 2E 73 65 74 52 65 71 75 65 73 74 50 72 6F 70 65 72 74 79 28 5C 22 52 45 46 45 52 45 52 5C 22 2C 20 5C 22 5C 22 2B 66 63 6B 61 6C 2B 5C 22 5C 22 29 3B}
		$s9 = {46 69 6C 65 4C 6F 63 61 6C 55 70 6C 6F 61 64 28 75 63 28 64 78 28 29 29 2B 73 78 6D 2C 72 65 71 75 65 73 74 2E 67 65 74 52 65 71 75 65 73 74 55 52 4C 28 29 2E 74 6F 53 74 72 69 6E 67 28 29 2C 20 20 5C 22 47 42 4B 5C 22 29 3B}

	condition:
		1 of them
}

rule webshell_Dive_Shell_1_0_Emperor_Hacking_Team_xxx
{
	meta:
		description = "Web Shell - from files Dive Shell 1.0 - Emperor Hacking Team.php, phpshell.php, SimShell 1.0 - Simorgh Security MGZ.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "1b5102bdc41a7bc439eea8f0010310a5"
		hash1 = "f8a6d5306fb37414c5c772315a27832f"
		hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"

	strings:
		$s1 = {69 66 20 28 28 24 69 20 3D 20 61 72 72 61 79 5F 73 65 61 72 63 68 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 2C 20 24 5F 53 45 53 53 49 4F 4E 5B 27 68 69 73 74 6F 72 79 27 5D 29 29 20 21 3D 3D 20 66 61 6C 73}
		$s9 = {69 66 20 28 65 72 65 67 28 27 5E 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2A 63 64 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2A 24 27 2C 20 24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 29 29 20 7B}

	condition:
		all of them
}

rule webshell_404_data_in_JFolder_jfolder01_xxx
{
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, suiyue.jsp, warn.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash3 = "8979594423b68489024447474d113894"
		hash4 = "ec482fc969d182e5440521c913bab9bd"
		hash5 = "f98d2b33cd777e160d1489afed96de39"
		hash6 = "4b4c12b3002fad88ca6346a873855209"
		hash7 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
		hash8 = "e9a5280f77537e23da2545306f6a19ad"

	strings:
		$s4 = {26 6E 62 73 70 3B 3C 54 45 58 54 41 52 45 41 20 4E 41 4D 45 3D 5C 22 63 71 71 5C 22 20 52 4F 57 53 3D 5C 22 32 30 5C 22 20 43 4F 4C 53 3D 5C 22 31 30 30 25 5C 22 3E 3C 25 3D 73 62 43 6D 64 2E 74 6F 53 74 72 69 6E 67 28 29 25 3E 3C 2F 54 45}

	condition:
		all of them
}

rule webshell_jsp_reverse_jsp_reverse_jspbd
{
	meta:
		description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		super_rule = 1
		hash0 = "8b0e6779f25a17f0ffb3df14122ba594"
		hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
		hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"
		score = 50

	strings:
		$s0 = {6F 73 77 20 3D 20 6E 65 77 20 42 75 66 66 65 72 65 64 57 72 69 74 65 72 28 6E 65 77 20 4F 75 74 70 75 74 53 74 72 65 61 6D 57 72 69 74 65 72 28 6F 73 29 29 3B}
		$s7 = {73 6F 63 6B 20 3D 20 6E 65 77 20 53 6F 63 6B 65 74 28 69 70 41 64 64 72 65 73 73 2C 20 28 6E 65 77 20 49 6E 74 65 67 65 72 28 69 70 50 6F 72 74 29 29 2E 69 6E 74 56 61 6C 75 65 28 29 29 3B}
		$s9 = {69 73 72 20 3D 20 6E 65 77 20 42 75 66 66 65 72 65 64 52 65 61 64 65 72 28 6E 65 77 20 49 6E 70 75 74 53 74 72 65 61 6D 52 65 61 64 65 72 28 69 73 29 29 3B}

	condition:
		all of them
}

rule webshell_400_in_JFolder_jfolder01_jsp_leo_warn_webshell_nc
{
	meta:
		description = "Web Shell - from files 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "36331f2c81bad763528d0ae00edf55be"
		hash1 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash2 = "8979594423b68489024447474d113894"
		hash3 = "ec482fc969d182e5440521c913bab9bd"
		hash4 = "f98d2b33cd777e160d1489afed96de39"
		hash5 = "4b4c12b3002fad88ca6346a873855209"
		hash6 = "e9a5280f77537e23da2545306f6a19ad"
		hash7 = "598eef7544935cf2139d1eada4375bb5"

	strings:
		$s0 = {73 62 46 6F 6C 64 65 72 2E 61 70 70 65 6E 64 28 5C 22 3C 74 72 3E 3C 74 64 20 3E 26 6E 62 73 70 3B 3C 2F 74 64 3E 3C 74 64 3E 5C 22 29 3B}
		$s1 = {72 65 74 75 72 6E 20 66 69 6C 65 73 69 7A 65 20 2F 20 69 6E 74 44 69 76 69 73 6F 72 20 2B 20 5C 22 2E 5C 22 20 2B 20 73 74 72 41 66 74 65 72 43 6F 6D 6D 61 20 2B 20 5C 22 20 5C 22 20 2B 20 73 74 72 55 6E 69 74 3B}
		$s5 = {46 69 6C 65 49 6E 66 6F 20 66 69 20 3D 20 28 46 69 6C 65 49 6E 66 6F 29 20 68 74 2E 67 65 74 28 5C 22 63 71 71 55 70 6C 6F 61 64 46 69 6C 65 5C 22 29 3B}
		$s6 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 63 6D 64 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 73 74 72 43 6D 64 25 3E 5C 22 3E}

	condition:
		2 of them
}

rule webshell_2_520_job_JspWebshell_1_2_ma1_ma4_2
{
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, JspWebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "56c005690da2558690c4aa305a31ad37"
		hash3 = "70a0ee2624e5bbe5525ccadc467519f6"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
		hash5 = "6e0fa491d620d4af4b67bae9162844ae"
		hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"

	strings:
		$s1 = {77 68 69 6C 65 20 28 28 6E 52 65 74 20 3D 20 69 6E 73 52 65 61 64 65 72 2E 72 65 61 64 28 74 6D 70 42 75 66 66 65 72 2C 20 30 2C 20 31 30 32 34 29 29 20 21 3D 20 2D 31 29 20 7B}
		$s6 = {70 61 73 73 77 6F 72 64 20 3D 20 28 53 74 72 69 6E 67 29 73 65 73 73 69 6F 6E 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 70 61 73 73 77 6F 72 64 5C 22 29 3B}
		$s7 = {69 6E 73 52 65 61 64 65 72 20 3D 20 6E 65 77 20 49 6E 70 75 74 53 74 72 65 61 6D 52 65 61 64 65 72 28 70 72 6F 63 2E 67 65 74 49 6E 70 75 74 53 74 72 65 61 6D 28 29 2C 20 43 68 61 72 73 65 74 2E 66 6F 72 4E 61 6D 65 28 5C 22 47 42 32 33 31}

	condition:
		2 of them
}

rule webshell_shell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz
{
	meta:
		description = "Web Shell - from files shell.php, 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 60
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
		hash3 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash4 = "40a1f840111996ff7200d18968e42cfe"
		hash5 = "e0202adff532b28ef1ba206cf95962f2"
		hash6 = "802f5cae46d394b297482fd0c27cb2fc"

	strings:
		$s0 = {24 74 61 62 6C 65 64 75 6D 70 20 2E 3D 20 5C 22 27 5C 22 2E 6D 79 73 71 6C 5F 65 73 63 61 70 65 5F 73 74 72 69 6E 67 28 24 72 6F 77 5B 24 66 69 65 6C 64 63 6F 75 6E 74 65 72 5D 29 2E 5C 22 27 5C 22 3B}
		$s5 = {77 68 69 6C 65 28 6C 69 73 74 28 24 6B 6E 61 6D 65 2C 20 24 63 6F 6C 75 6D 6E 73 29 20 3D 20 40 65 61 63 68 28 24 69 6E 64 65 78 29 29 20 7B}
		$s6 = {24 74 61 62 6C 65 64 75 6D 70 20 3D 20 5C 22 44 52 4F 50 20 54 41 42 4C 45 20 49 46 20 45 58 49 53 54 53 20 24 74 61 62 6C 65 3B 5C 5C 6E 5C 22 3B}
		$s9 = {24 74 61 62 6C 65 64 75 6D 70 20 2E 3D 20 5C 22 20 20 20 50 52 49 4D 41 52 59 20 4B 45 59 20 28 24 63 6F 6C 6E 61 6D 65 73 29 5C 22 3B}
		$fn = {66 69 6C 65 6E 61 6D 65 3A 20 62 61 63 6B 75 70}

	condition:
		2 of ($s*) and not $fn
}

rule webshell_gfs_sh_r57shell_r57shell127_SnIpEr_SA_xxx
{
	meta:
		description = "Web Shell - from files gfs_sh.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "a2516ac6ee41a7cf931cbaef1134a9e4"
		hash1 = "ef43fef943e9df90ddb6257950b3538f"
		hash2 = "ae025c886fbe7f9ed159f49593674832"
		hash3 = "911195a9b7c010f61b66439d9048f400"
		hash4 = "697dae78c040150daff7db751fc0c03c"
		hash5 = "513b7be8bd0595c377283a7c87b44b2e"
		hash6 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash7 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash8 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash9 = "41af6fd253648885c7ad2ed524e0692d"
		hash10 = "6fcc283470465eed4870bcc3e2d7f14d"

	strings:
		$s0 = {6B 56 79 63 6D 39 79 4F 69 41 6B 49 56 78 75 49 69 6B 37 44 51 70 6A 62 32 35 75 5A 57 4E 30 4B 46 4E 50 51 30 74 46 56 43 77 67 4A 48 42 68 5A 47 52 79 4B 53 42 38 66 43 42 6B 61 57 55 6F 49 6B 56 79 63 6D 39 79 4F 69 41 6B 49 56 78 75 49}
		$s11 = {41 6F 63 33 52 79 64 57 4E 30 49 48 4E 76 59 32 74 68 5A 47 52 79 49 43 6F 70 49 43 5A 7A 61 57 34 73 49 48 4E 70 65 6D 56 76 5A 69 68 7A 64 48 4A 31 59 33 51 67 63 32 39 6A 61 32 46 6B 5A 48 49 70 4B 53 6B 38 4D 43 6B 67 65 77 30 4B 49 43}

	condition:
		all of them
}

rule webshell_itsec_PHPJackal_itsecteam_shell_jHn
{
	meta:
		description = "Web Shell - from files itsec.php, PHPJackal.php, itsecteam_shell.php, jHn.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
		hash1 = "e2830d3286001d1455479849aacbbb38"
		hash2 = "bd6d3b2763c705a01cc2b3f105a25fa4"
		hash3 = "40c6ecf77253e805ace85f119fe1cebb"

	strings:
		$s0 = {24 6C 69 6E 6B 3D 70 67 5F 63 6F 6E 6E 65 63 74 28 5C 22 68 6F 73 74 3D 24 68 6F 73 74 20 64 62 6E 61 6D 65 3D 24 64 62 20 75 73 65 72 3D 24 75 73 65 72 20 70 61 73 73 77 6F 72 64 3D 24 70 61 73 73 5C 22 29 3B}
		$s6 = {77 68 69 6C 65 28 24 64 61 74 61 3D 6F 63 69 66 65 74 63 68 69 6E 74 6F 28 24 73 74 6D 2C 24 64 61 74 61 2C 4F 43 49 5F 41 53 53 4F 43 2B 4F 43 49 5F 52 45 54 55 52 4E 5F 4E 55 4C 4C 53 29 29 24 72 65 73 2E 3D 69 6D 70 6C 6F 64 65 28 27 7C}
		$s9 = {77 68 69 6C 65 28 24 64 61 74 61 3D 70 67 5F 66 65 74 63 68 5F 72 6F 77 28 24 72 65 73 75 6C 74 29 29 24 72 65 73 2E 3D 69 6D 70 6C 6F 64 65 28 27 7C 2D 7C 2D 7C 2D 7C 2D 7C 2D 7C 27 2C 24 64 61 74 61 29 2E 27 7C 2B 7C 2B 7C 2B 7C 2B 7C 2B}

	condition:
		2 of them
}

rule webshell_Shell_ci_Biz_was_here_c100_v_xxx
{
	meta:
		description = "Web Shell - from files Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c99-shadows-mod.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "f2fa878de03732fbf5c86d656467ff50"
		hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"

	strings:
		$s2 = {69 66 20 28 24 64 61 74 61 7B 30 7D 20 3D 3D 20 5C 22 5C 5C 78 39 39 5C 22 20 61 6E 64 20 24 64 61 74 61 7B 31 7D 20 3D 3D 20 5C 22 5C 5C 78 30 31 5C 22 29 20 7B 72 65 74 75 72 6E 20 5C 22 45 72 72 6F 72 3A 20 5C 22 2E 24 73 74 72 69}
		$s3 = {3C 4F 50 54 49 4F 4E 20 56 41 4C 55 45 3D 5C 22 66 69 6E 64 20 2F 65 74 63 2F 20 2D 74 79 70 65 20 66 20 2D 70 65 72 6D 20 2D 6F 2B 77 20 32 3E 20 2F 64 65 76 2F 6E 75 6C 6C 5C 22}
		$s4 = {3C 4F 50 54 49 4F 4E 20 56 41 4C 55 45 3D 5C 22 63 61 74 20 2F 70 72 6F 63 2F 76 65 72 73 69 6F 6E 20 2F 70 72 6F 63 2F 63 70 75 69 6E 66 6F 5C 22 3E 43 50 55 49 4E 46 4F}
		$s7 = {3C 4F 50 54 49 4F 4E 20 56 41 4C 55 45 3D 5C 22 77 67 65 74 20 68 74 74 70 3A 2F 2F 66 74 70 2E 70 6F 77 65 72 6E 65 74 2E 63 6F 6D 2E 74 72 2F 73 75 70 65 72 6D 61 69 6C 2F 64 65}
		$s9 = {3C 4F 50 54 49 4F 4E 20 56 41 4C 55 45 3D 5C 22 63 75 74 20 2D 64 3A 20 2D 66 31 2C 32 2C 33 20 2F 65 74 63 2F 70 61 73 73 77 64 20 7C 20 67 72 65 70 20 3A 3A 5C 22 3E 55 53 45 52}

	condition:
		2 of them
}

rule webshell_NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_xxx1
{
	meta:
		description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, KAdot Universal Shell v0.1.6.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
		hash1 = "f3ca29b7999643507081caab926e2e74"
		hash2 = "527cf81f9272919bf872007e21c4bdda"

	strings:
		$s1 = {3C 74 64 3E 3C 69 6E 70 75 74 20 73 69 7A 65 3D 5C 22 34 38 5C 22 20 76 61 6C 75 65 3D 5C 22 24 64 6F 63 72 2F 5C 22 20 6E 61 6D 65 3D 5C 22 70 61 74 68 5C 22 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D}
		$s2 = {24 75 70 6C 6F 61 64 66 69 6C 65 20 3D 20 24 5F 50 4F 53 54 5B 27 70 61 74 68 27 5D 2E 24 5F 46 49 4C 45 53 5B 27 66 69 6C 65 27 5D 5B 27 6E 61 6D 65 27 5D 3B}
		$s6 = {65 6C 73 65 69 66 20 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 61 63 27 5D 29 29 20 7B 24 61 63 20 3D 20 24 5F 50 4F 53 54 5B 27 61 63 27 5D 3B 7D}
		$s7 = {69 66 20 28 24 5F 50 4F 53 54 5B 27 70 61 74 68 27 5D 3D 3D 5C 22 5C 22 29 7B 24 75 70 6C 6F 61 64 66 69 6C 65 20 3D 20 24 5F 46 49 4C 45 53 5B 27 66 69 6C 65 27 5D 5B 27 6E 61 6D 65 27 5D 3B 7D}

	condition:
		2 of them
}

rule webshell_c99_c99shell_c99_w4cking_Shell_xxx
{
	meta:
		description = "Web Shell - from files c99.php, c99shell.php, c99_w4cking.php, Shell [ci] .Biz was here.php, acid.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "d3f38a6dc54a73d304932d9227a739ec"
		hash2 = "9c34adbc8fd8d908cbb341734830f971"
		hash3 = "f2fa878de03732fbf5c86d656467ff50"
		hash4 = "b8f261a3cdf23398d573aaf55eaf63b5"
		hash5 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash6 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash7 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash8 = "157b4ac3c7ba3a36e546e81e9279eab5"
		hash9 = "048ccc01b873b40d57ce25a4c56ea717"

	strings:
		$s0 = {65 63 68 6F 20 5C 22 3C 62 3E 48 45 58 44 55 4D 50 3A 3C 2F 62 3E 3C 6E 6F 62 72 3E}
		$s4 = {69 66 20 28 24 66 69 6C 65 73 74 65 61 6C 74 68 29 20 7B 24 73 74 61 74 20 3D 20 73 74 61 74 28 24 64 2E 24 66 29 3B 7D}
		$s5 = {77 68 69 6C 65 20 28 24 72 6F 77 20 3D 20 6D 79 73 71 6C 5F 66 65 74 63 68 5F 61 72 72 61 79 28 24 72 65 73 75 6C 74 2C 20 4D 59 53 51 4C 5F 4E 55 4D 29 29 20 7B 20 65 63 68 6F 20 5C 22 3C 74 72 3E 3C 74 64 3E 5C 22 2E 24 72}
		$s6 = {69 66 20 28 28 6D 79 73 71 6C 5F 63 72 65 61 74 65 5F 64 62 20 28 24 73 71 6C 5F 6E 65 77 64 62 29 29 20 61 6E 64 20 28 21 65 6D 70 74 79 28 24 73 71 6C 5F 6E 65 77 64 62 29 29 29 20 7B 65 63 68 6F 20 5C 22 44 42 20}
		$s8 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 62 3E 53 65 72 76 65 72 2D 73 74 61 74 75 73 20 76 61 72 69 61 62 6C 65 73 3A 3C 2F 62 3E 3C 62 72 3E 3C 62 72 3E 5C 22 3B}
		$s9 = {65 63 68 6F 20 5C 22 3C 74 65 78 74 61 72 65 61 20 63 6F 6C 73 3D 38 30 20 72 6F 77 73 3D 31 30 3E 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 65 6E 63 6F 64 65 64 29 2E 5C 22 3C 2F 74 65 78 74 61 72 65 61 3E}

	condition:
		2 of them
}

rule webshell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz
{
	meta:
		description = "Web Shell - from files 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
		hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "802f5cae46d394b297482fd0c27cb2fc"

	strings:
		$s0 = {24 74 68 69 73 20 2D 3E 20 61 64 64 46 69 6C 65 28 24 63 6F 6E 74 65 6E 74 2C 20 24 66 69 6C 65 6E 61 6D 65 29 3B}
		$s3 = {66 75 6E 63 74 69 6F 6E 20 61 64 64 46 69 6C 65 28 24 64 61 74 61 2C 20 24 6E 61 6D 65 2C 20 24 74 69 6D 65 20 3D 20 30 29 20 7B}
		$s8 = {66 75 6E 63 74 69 6F 6E 20 75 6E 69 78 32 44 6F 73 54 69 6D 65 28 24 75 6E 69 78 74 69 6D 65 20 3D 20 30 29 20 7B}
		$s9 = {66 6F 72 65 61 63 68 28 24 66 69 6C 65 6C 69 73 74 20 61 73 20 24 66 69 6C 65 6E 61 6D 65 29 7B}

	condition:
		all of them
}

rule webshell_c99_c66_c99_shadows_mod_c99shell
{
	meta:
		description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash3 = "048ccc01b873b40d57ce25a4c56ea717"

	strings:
		$s2 = {20 20 69 66 20 28 75 6E 6C 69 6E 6B 28 5F 46 49 4C 45 5F 29 29 20 7B 40 6F 62 5F 63 6C 65 61 6E 28 29 3B 20 65 63 68 6F 20 5C 22 54 68 61 6E 6B 73 20 66 6F 72 20 75 73 69 6E 67 20 63 39 39 73 68 65 6C 6C 20 76 2E 5C 22 2E 24 73 68 76}
		$s3 = {20 20 5C 22 63 39 39 73 68 5F 62 61 63 6B 63 6F 6E 6E 2E 70 6C 5C 22 3D 3E 61 72 72 61 79 28 5C 22 55 73 69 6E 67 20 50 45 52 4C 5C 22 2C 5C 22 70 65 72 6C 20 25 70 61 74 68 20 25 68 6F 73 74 20 25 70 6F 72 74 5C 22 29 2C}
		$s4 = {3C 62 72 3E 3C 54 41 42 4C 45 20 73 74 79 6C 65 3D 5C 22 42 4F 52 44 45 52 2D 43 4F 4C 4C 41 50 53 45 3A 20 63 6F 6C 6C 61 70 73 65 5C 22 20 63 65 6C 6C 53 70 61 63 69 6E 67 3D 30 20 62 6F 72 64 65 72 43 6F 6C 6F 72 44 61 72 6B 3D 23 36 36}
		$s7 = {20 20 20 65 6C 73 65 69 66 20 28 21 24 64 61 74 61 20 3D 20 63 39 39 67 65 74 73 6F 75 72 63 65 28 24 62 69 6E 64 5B 5C 22 73 72 63 5C 22 5D 29 29 20 7B 65 63 68 6F 20 5C 22 43 61 6E 27 74 20 64 6F 77 6E 6C 6F 61 64 20 73 6F 75 72 63 65 73}
		$s8 = {20 20 5C 22 63 39 39 73 68 5F 64 61 74 61 70 69 70 65 2E 70 6C 5C 22 3D 3E 61 72 72 61 79 28 5C 22 55 73 69 6E 67 20 50 45 52 4C 5C 22 2C 5C 22 70 65 72 6C 20 25 70 61 74 68 20 25 6C 6F 63 61 6C 70 6F 72 74 20 25 72 65 6D 6F 74 65 68 6F 73}
		$s9 = {20 20 20 65 6C 73 65 69 66 20 28 21 24 64 61 74 61 20 3D 20 63 39 39 67 65 74 73 6F 75 72 63 65 28 24 62 63 5B 5C 22 73 72 63 5C 22 5D 29 29 20 7B 65 63 68 6F 20 5C 22 43 61 6E 27 74 20 64 6F 77 6E 6C 6F 61 64 20 73 6F 75 72 63 65 73 21}

	condition:
		2 of them
}

rule webshell_he1p_JspSpy_nogfw_ok_style_1_JspSpy1
{
	meta:
		description = "Web Shell - from files he1p.jsp, JspSpy.jsp, nogfw.jsp, ok.jsp, style.jsp, 1.jsp, JspSpy.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b330a6c2d49124ef0729539761d6ef0b"
		hash1 = "d71716df5042880ef84427acee8b121e"
		hash2 = "344f9073576a066142b2023629539ebd"
		hash3 = "32dea47d9c13f9000c4c807561341bee"
		hash4 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash5 = "3ea688e3439a1f56b16694667938316d"
		hash6 = "2434a7a07cb47ce25b41d30bc291cacc"

	strings:
		$s0 = {5C 22 5C 22 2B 66 2E 63 61 6E 52 65 61 64 28 29 2B 5C 22 20 2F 20 5C 22 2B 66 2E 63 61 6E 57 72 69 74 65 28 29 2B 5C 22 20 2F 20 5C 22 2B 66 2E 63 61 6E 45 78 65 63 75 74 65 28 29 2B 5C 22 3C 2F 74 64 3E 5C 22 2B}
		$s4 = {6F 75 74 2E 70 72 69 6E 74 6C 6E 28 5C 22 3C 68 32 3E 46 69 6C 65 20 4D 61 6E 61 67 65 72 20 2D 20 43 75 72 72 65 6E 74 20 64 69 73 6B 20 26 71 75 6F 74 3B 5C 22 2B 28 63 72 2E 69 6E 64 65 78 4F 66 28 5C 22 2F 5C 22 29 20 3D 3D 20 30 3F}
		$s7 = {53 74 72 69 6E 67 20 65 78 65 63 75 74 65 20 3D 20 66 2E 63 61 6E 45 78 65 63 75 74 65 28 29 20 3F 20 5C 22 63 68 65 63 6B 65 64 3D 5C 5C 5C 22 63 68 65 63 6B 65 64 5C 5C 5C 22 5C 22 20 3A 20 5C 22 5C 22 3B}
		$s8 = {5C 22 3C 74 64 20 6E 6F 77 72 61 70 3E 5C 22 2B 66 2E 63 61 6E 52 65 61 64 28 29 2B 5C 22 20 2F 20 5C 22 2B 66 2E 63 61 6E 57 72 69 74 65 28 29 2B 5C 22 20 2F 20 5C 22 2B 66 2E 63 61 6E 45 78 65 63 75 74 65 28 29 2B 5C 22 3C 2F 74 64 3E}

	condition:
		2 of them
}

rule webshell_000_403_c5_config_myxx_queryDong_spyjsp2010_zend
{
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash4 = "e0354099bee243702eb11df8d0e046df"
		hash5 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash6 = "655722eaa6c646437c8ae93daac46ae0"
		hash7 = "591ca89a25f06cf01e4345f98a22845c"

	strings:
		$s0 = {72 65 74 75 72 6E 20 6E 65 77 20 44 6F 75 62 6C 65 28 66 6F 72 6D 61 74 2E 66 6F 72 6D 61 74 28 76 61 6C 75 65 29 29 2E 64 6F 75 62 6C 65 56 61 6C 75 65 28 29 3B}
		$s5 = {46 69 6C 65 20 74 65 6D 70 46 20 3D 20 6E 65 77 20 46 69 6C 65 28 73 61 76 65 50 61 74 68 29 3B}
		$s9 = {69 66 20 28 74 65 6D 70 46 2E 69 73 44 69 72 65 63 74 6F 72 79 28 29 29 20 7B}

	condition:
		2 of them
}

rule webshell_c99_c99shell_c99_c99shell
{
	meta:
		description = "Web Shell - from files c99.php, c99shell.php, c99.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "d3f38a6dc54a73d304932d9227a739ec"
		hash2 = "157b4ac3c7ba3a36e546e81e9279eab5"
		hash3 = "048ccc01b873b40d57ce25a4c56ea717"

	strings:
		$s2 = {24 62 69 6E 64 70 6F 72 74 5F 70 61 73 73 20 3D 20 5C 22 63 39 39 5C 22 3B}
		$s5 = {20 65 6C 73 65 20 7B 65 63 68 6F 20 5C 22 3C 62 3E 45 78 65 63 75 74 69 6F 6E 20 50 48 50 2D 63 6F 64 65 3C 2F 62 3E 5C 22 3B 20 69 66 20 28 65 6D 70 74 79 28 24 65 76 61 6C 5F 74 78 74 29 29 20 7B 24 65 76 61 6C 5F 74 78 74 20 3D 20 74 72}

	condition:
		1 of them
}

rule webshell_r57shell127_r57_iFX_r57_kartal_r57_antichat
{
	meta:
		description = "Web Shell - from files r57shell127.php, r57_iFX.php, r57_kartal.php, r57.php, antichat.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae025c886fbe7f9ed159f49593674832"
		hash1 = "513b7be8bd0595c377283a7c87b44b2e"
		hash2 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash3 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash4 = "3f71175985848ee46cc13282fbed2269"

	strings:
		$s6 = {24 72 65 73 20 20 20 3D 20 40 6D 79 73 71 6C 5F 71 75 65 72 79 28 5C 22 53 48 4F 57 20 43 52 45 41 54 45 20 54 41 42 4C 45 20 60 5C 22 2E 24 5F 50 4F 53 54 5B 27 6D 79 73 71 6C 5F 74 62 6C 27 5D 2E 5C 22 60 5C 22 2C 20 24 64}
		$s7 = {24 73 71 6C 31 20 2E 3D 20 24 72 6F 77 5B 31 5D 2E 5C 22 5C 5C 72 5C 5C 6E 5C 5C 72 5C 5C 6E 5C 22 3B}
		$s8 = {69 66 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 64 69 66 27 5D 29 26 26 24 66 70 29 20 7B 20 40 66 70 75 74 73 28 24 66 70 2C 24 73 71 6C 31 2E 24 73 71 6C 32 29 3B 20 7D}
		$s9 = {66 6F 72 65 61 63 68 28 24 76 61 6C 75 65 73 20 61 73 20 24 6B 3D 3E 24 76 29 20 7B 24 76 61 6C 75 65 73 5B 24 6B 5D 20 3D 20 61 64 64 73 6C 61 73 68 65 73 28 24 76 29 3B 7D}

	condition:
		2 of them
}

rule webshell_NIX_REMOTE_WEB_SHELL_nstview_xxx
{
	meta:
		description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, nstview.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, Cyber Shell (v 1.0).php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
		hash1 = "4745d510fed4378e4b1730f56f25e569"
		hash2 = "f3ca29b7999643507081caab926e2e74"
		hash3 = "46a18979750fa458a04343cf58faa9bd"

	strings:
		$s3 = {42 4F 44 59 2C 20 54 44 2C 20 54 52 20 7B}
		$s5 = {24 64 3D 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 22 2C 5C 22 2F 5C 22 2C 24 64 29 3B}
		$s6 = {69 66 20 28 24 66 69 6C 65 3D 3D 5C 22 2E 5C 22 20 7C 7C 20 24 66 69 6C 65 3D 3D 5C 22 2E 2E 5C 22 29 20 63 6F 6E 74 69 6E 75 65 3B}

	condition:
		2 of them
}

rule webshell_000_403_807_a_c5_config_css_dm_he1p_xxx
{
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash7 = "14e9688c86b454ed48171a9d4f48ace8"
		hash8 = "b330a6c2d49124ef0729539761d6ef0b"
		hash9 = "d71716df5042880ef84427acee8b121e"
		hash10 = "341298482cf90febebb8616426080d1d"
		hash11 = "29aebe333d6332f0ebc2258def94d57e"
		hash12 = "42654af68e5d4ea217e6ece5389eb302"
		hash13 = "88fc87e7c58249a398efd5ceae636073"
		hash14 = "4a812678308475c64132a9b56254edbc"
		hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash16 = "e0354099bee243702eb11df8d0e046df"
		hash17 = "344f9073576a066142b2023629539ebd"
		hash18 = "32dea47d9c13f9000c4c807561341bee"
		hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash20 = "655722eaa6c646437c8ae93daac46ae0"
		hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash22 = "6acc82544be056580c3a1caaa4999956"
		hash23 = "6aa32a6392840e161a018f3907a86968"
		hash24 = "591ca89a25f06cf01e4345f98a22845c"
		hash25 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash26 = "3ea688e3439a1f56b16694667938316d"
		hash27 = "ab77e4d1006259d7cbc15884416ca88c"
		hash28 = "71097537a91fac6b01f46f66ee2d7749"
		hash29 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash30 = "7a4b090619ecce6f7bd838fe5c58554b"

	strings:
		$s3 = {53 74 72 69 6E 67 20 73 61 76 65 50 61 74 68 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 73 61 76 65 70 61 74 68 5C 22 29 3B}
		$s4 = {55 52 4C 20 64 6F 77 6E 55 72 6C 20 3D 20 6E 65 77 20 55 52 4C 28 64 6F 77 6E 46 69 6C 65 55 72 6C 29 3B}
		$s5 = {69 66 20 28 55 74 69 6C 2E 69 73 45 6D 70 74 79 28 64 6F 77 6E 46 69 6C 65 55 72 6C 29 20 7C 7C 20 55 74 69 6C 2E 69 73 45 6D 70 74 79 28 73 61 76 65 50 61 74 68 29 29}
		$s6 = {53 74 72 69 6E 67 20 64 6F 77 6E 46 69 6C 65 55 72 6C 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 75 72 6C 5C 22 29 3B}
		$s7 = {46 69 6C 65 49 6E 70 75 74 53 74 72 65 61 6D 20 66 49 6E 70 75 74 20 3D 20 6E 65 77 20 46 69 6C 65 49 6E 70 75 74 53 74 72 65 61 6D 28 66 29 3B}
		$s8 = {55 52 4C 43 6F 6E 6E 65 63 74 69 6F 6E 20 63 6F 6E 6E 20 3D 20 64 6F 77 6E 55 72 6C 2E 6F 70 65 6E 43 6F 6E 6E 65 63 74 69 6F 6E 28 29 3B}
		$s9 = {73 69 73 20 3D 20 72 65 71 75 65 73 74 2E 67 65 74 49 6E 70 75 74 53 74 72 65 61 6D 28 29 3B}

	condition:
		4 of them
}

rule webshell_2_520_icesword_job_ma1
{
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
		hash3 = "56c005690da2558690c4aa305a31ad37"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"

	strings:
		$s1 = {3C 6D 65 74 61 20 68 74 74 70 2D 65 71 75 69 76 3D 5C 22 43 6F 6E 74 65 6E 74 2D 54 79 70 65 5C 22 20 63 6F 6E 74 65 6E 74 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 20 63 68 61 72 73 65 74 3D 67 62 32 33 31 32 5C 22 3E 3C 2F 68 65 61 64 3E}
		$s3 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 5F 45 56 45 4E 54 54 41 52 47 45 54 5C 22 20 76 61 6C 75 65 3D 5C 22 5C 22 20 2F 3E}
		$s8 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 5F 45 56 45 4E 54 41 52 47 55 4D 45 4E 54 5C 22 20 76 61 6C 75 65 3D 5C 22 5C 22 20 2F 3E}

	condition:
		2 of them
}

rule webshell_404_data_in_JFolder_jfolder01_jsp_suiyue_warn
{
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash3 = "8979594423b68489024447474d113894"
		hash4 = "ec482fc969d182e5440521c913bab9bd"
		hash5 = "f98d2b33cd777e160d1489afed96de39"
		hash6 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
		hash7 = "e9a5280f77537e23da2545306f6a19ad"

	strings:
		$s0 = {3C 74 61 62 6C 65 20 77 69 64 74 68 3D 5C 22 31 30 30 25 5C 22 20 62 6F 72 64 65 72 3D 5C 22 31 5C 22 20 63 65 6C 6C 73 70 61 63 69 6E 67 3D 5C 22 30 5C 22 20 63 65 6C 6C 70 61 64 64 69 6E 67 3D 5C 22 35 5C 22 20 62 6F 72 64 65 72 63 6F 6C}
		$s2 = {20 4B 42 20 3C 2F 74 64 3E}
		$s3 = {3C 74 61 62 6C 65 20 77 69 64 74 68 3D 5C 22 39 38 25 5C 22 20 62 6F 72 64 65 72 3D 5C 22 30 5C 22 20 63 65 6C 6C 73 70 61 63 69 6E 67 3D 5C 22 30 5C 22 20 63 65 6C 6C 70 61 64 64 69 6E 67 3D 5C 22}
		$s4 = {3C 21 2D 2D 20 3C 74 72 20 61 6C 69 67 6E 3D 5C 22 63 65 6E 74 65 72 5C 22 3E 20}

	condition:
		all of them
}

rule webshell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_PHPSPY
{
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
		hash2 = "40a1f840111996ff7200d18968e42cfe"
		hash3 = "0712e3dc262b4e1f98ed25760b206836"

	strings:
		$s4 = {68 74 74 70 3A 2F 2F 77 77 77 2E 34 6E 67 65 6C 2E 6E 65 74}
		$s5 = {3C 2F 61 3E 20 7C 20 3C 61 20 68 72 65 66 3D 5C 22 3F 61 63 74 69 6F 6E 3D 70 68 70 65 6E 76 5C 22 3E 50 48 50}
		$s8 = {65 63 68 6F 20 24 6D 73 67 3D 40 66 77 72 69 74 65 28 24 66 70 2C 24 5F 50 4F 53 54 5B 27 66 69 6C 65 63 6F 6E 74 65 6E 74 27 5D 29 20 3F 20 5C 22}
		$s9 = {43 6F 64 7A 20 62 79 20 41 6E 67 65 6C}

	condition:
		2 of them
}

rule webshell_c99_locus7s_c99_w4cking_xxx
{
	meta:
		description = "Web Shell - from files c99_locus7s.php, c99_w4cking.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, acid.php, newsh.php, r57.php, Backdoor.PHP.Agent.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "38fd7e45f9c11a37463c3ded1c76af4c"
		hash1 = "9c34adbc8fd8d908cbb341734830f971"
		hash2 = "ef43fef943e9df90ddb6257950b3538f"
		hash3 = "ae025c886fbe7f9ed159f49593674832"
		hash4 = "911195a9b7c010f61b66439d9048f400"
		hash5 = "697dae78c040150daff7db751fc0c03c"
		hash6 = "513b7be8bd0595c377283a7c87b44b2e"
		hash7 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash8 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash9 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash10 = "b8f261a3cdf23398d573aaf55eaf63b5"
		hash11 = "0d2c2c151ed839e6bafc7aa9c69be715"
		hash12 = "41af6fd253648885c7ad2ed524e0692d"
		hash13 = "6fcc283470465eed4870bcc3e2d7f14d"

	strings:
		$s1 = {24 72 65 73 20 3D 20 40 73 68 65 6C 6C 5F 65 78 65 63 28 24 63 66 65 29 3B}
		$s8 = {24 72 65 73 20 3D 20 40 6F 62 5F 67 65 74 5F 63 6F 6E 74 65 6E 74 73 28 29 3B}
		$s9 = {40 65 78 65 63 28 24 63 66 65 2C 24 72 65 73 29 3B}

	condition:
		2 of them
}

rule webshell_browser_201_3_ma_ma2_download
{
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash4 = "4b45715fa3fa5473640e17f49ef5513d"
		hash5 = "fa87bbd7201021c1aefee6fcc5b8e25a"

	strings:
		$s1 = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 66 69 6E 61 6C 20 69 6E 74 20 45 44 49 54 46 49 45 4C 44 5F 52 4F 57 53 20 3D 20 33 30 3B}
		$s2 = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 53 74 72 69 6E 67 20 74 65 6D 70 64 69 72 20 3D 20 5C 22 2E 5C 22 3B}
		$s6 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 64 69 72 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 72 65 71 75 65 73 74 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 64 69 72 5C 22 29 25 3E 5C 22}

	condition:
		2 of them
}

rule webshell_000_403_c5_queryDong_spyjsp2010
{
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash4 = "655722eaa6c646437c8ae93daac46ae0"

	strings:
		$s2 = {5C 22 20 3C 73 65 6C 65 63 74 20 6E 61 6D 65 3D 27 65 6E 63 6F 64 65 27 20 63 6C 61 73 73 3D 27 69 6E 70 75 74 27 3E 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 27 27 3E 41 4E 53 49 3C 2F 6F 70 74 69 6F 6E 3E 3C 6F 70 74 69 6F 6E 20 76 61 6C}
		$s7 = {4A 53 65 73 73 69 6F 6E 2E 73 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 4D 53 47 5C 22 2C 5C 22 3C 73 70 61 6E 20 73 74 79 6C 65 3D 27 63 6F 6C 6F 72 3A 72 65 64 27 3E 55 70 6C 6F 61 64 20 46 69 6C 65 20 46 61 69 6C 65 64 21 3C 2F 73 70 61}
		$s8 = {46 69 6C 65 20 66 20 3D 20 6E 65 77 20 46 69 6C 65 28 4A 53 65 73 73 69 6F 6E 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 43 55 52 52 45 4E 54 5F 44 49 52 29 2B 5C 22 2F 5C 22 2B 66 69 6C 65 42 65 61 6E 2E 67 65 74 46 69 6C 65 4E 61 6D 65 28}
		$s9 = {28 28 49 6E 76 6F 6B 65 72 29 69 6E 73 2E 67 65 74 28 5C 22 76 64 5C 22 29 29 2E 69 6E 76 6F 6B 65 28 72 65 71 75 65 73 74 2C 72 65 73 70 6F 6E 73 65 2C 4A 53 65 73 73 69 6F 6E 29 3B}

	condition:
		2 of them
}

rule webshell_r57shell127_r57_kartal_r57
{
	meta:
		description = "Web Shell - from files r57shell127.php, r57_kartal.php, r57.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae025c886fbe7f9ed159f49593674832"
		hash1 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash2 = "4108f28a9792b50d95f95b9e5314fa1e"

	strings:
		$s2 = {24 68 61 6E 64 6C 65 20 3D 20 40 6F 70 65 6E 64 69 72 28 24 64 69 72 29 20 6F 72 20 64 69 65 28 5C 22 43 61 6E 27 74 20 6F 70 65 6E 20 64 69 72 65 63 74 6F 72 79 20 24 64 69 72 5C 22 29 3B}
		$s3 = {69 66 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 6D 79 73 71 6C 5F 64 62 27 5D 29 29 20 7B 20 40 6D 73 73 71 6C 5F 73 65 6C 65 63 74 5F 64 62 28 24 5F 50 4F 53 54 5B 27 6D 79 73 71 6C 5F 64 62 27 5D 2C 24 64 62 29 3B 20 7D}
		$s5 = {69 66 20 28 21 69 73 73 65 74 28 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 41 55 54 48 5F 55 53 45 52 27 5D 29 20 7C 7C 20 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 41 55 54 48 5F 55 53 45 52 27 5D 21 3D 3D 24 6E 61 6D 65 20 7C 7C 20 24 5F}

	condition:
		2 of them
}

rule webshell_webshells_new_con2
{
	meta:
		description = "Web shells - generated from file con2.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "d3584159ab299d546bd77c9654932ae3"

	strings:
		$s7 = {2C 68 74 61 50 72 65 77 6F 50 28 65 63 61 6C 70 65 72 3D 68 74 61 50 72 65 77 6F 50 3A 66 49 20 64 6E 45 3A 30 3D 4B 4F 74 69 64 45 3A 31 20 2D 20 65 75 6C 61 56 74 6E 69 20 3D 20 65 75 6C 61 56 74 6E 69 3A 6E 65 68 54 20 31 20 3D 3E 20 65}
		$s10 = {6A 20 5C 22 3C 46 6F 72 6D 20 61 63 74 69 6F 6E 3D 27 5C 22 26 55 52 4C 26 5C 22 3F 41 63 74 69 6F 6E 32 3D 50 6F 73 74 27 20 6D 65 74 68 6F 64 3D 27 70 6F 73 74 27 20 6E 61 6D 65 3D 27 45 64 69 74 46 6F 72 6D 27 3E 3C 69 6E 70 75 74 20 6E}

	condition:
		1 of them
}

rule webshell_webshells_new_make2
{
	meta:
		description = "Web shells - generated from file make2.php"
		author = "Florian Roth"
		date = "2014/03/28"
		hash = "9af195491101e0816a263c106e4c145e"
		score = 50

	strings:
		$s1 = {65 72 72 6F 72 5F 72 65 70 6F 72 74 69 6E 67 28 30 29 3B 73 65 73 73 69 6F 6E 5F 73 74 61 72 74 28 29 3B 68 65 61 64 65 72 28 5C 22 43 6F 6E 74 65 6E 74 2D 74 79 70 65 3A 74 65 78 74 2F 68 74 6D 6C 3B 63 68 61 72 73 65 74 3D 75 74 66 2D 38}

	condition:
		all of them
}

rule webshell_webshells_new_aaa
{
	meta:
		description = "Web shells - generated from file aaa.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "68483788ab171a155db5266310c852b2"

	strings:
		$s0 = {46 75 6E 63 74 69 6F 6E 20 66 76 6D 28 6A 77 76 29 3A 49 66 20 6A 77 76 3D 5C 22 5C 22 54 68 65 6E 3A 66 76 6D 3D 6A 77 76 3A 45 78 69 74 20 46 75 6E 63 74 69 6F 6E 3A 45 6E 64 20 49 66 3A 44 69 6D 20 74 74 2C 73 72 75 3A 74 74 3D 5C 22}
		$s5 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 5C 22 44 52 4F 50 20 54 41 42 4C 45 20 5B 6A 6E 63 5D 3B 65 78 65 63 20 6D 61 73 74 5C 22 26 6B 76 70 26 5C 22 65 72 2E 2E 78 70 5F 72 65 67 77 72 69 74 65 20 27 48 4B 45 59 5F 4C 4F 43 41 4C}
		$s17 = {69 66 20 71 70 76 3D 5C 22 5C 22 20 74 68 65 6E 20 71 70 76 3D 5C 22 78 3A 5C 5C 50 72 6F 67 72 61 6D 20 46 69 6C 65 73 5C 5C 4D 79 53 51 4C 5C 5C 4D 79 53 51 4C 20 53 65 72 76 65 72 20 35 2E 30 5C 5C 6D 79 2E 69 6E 69 5C 22 26 62 72 26}

	condition:
		1 of them
}

rule webshell_Expdoor_com_ASP
{
	meta:
		description = "Web shells - generated from file Expdoor.com ASP.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "caef01bb8906d909f24d1fa109ea18a7"

	strings:
		$s4 = {5C 22 3E 77 77 77 2E 45 78 70 64 6F 6F 72 2E 63 6F 6D 3C 2F 61 3E}
		$s5 = {20 20 20 20 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 46 69 6C 65 4E 61 6D 65 5C 22 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 76 61 6C 75 65 3D 5C 22 41 73 70 5F 76 65 72 2E 41 73 70 5C 22 20 73 69 7A 65 3D 5C 22 32 30 5C 22 20 6D 61 78}
		$s10 = {73 65 74 20 66 69 6C 65 3D 66 73 2E 4F 70 65 6E 54 65 78 74 46 69 6C 65 28 73 65 72 76 65 72 2E 4D 61 70 50 61 74 68 28 46 69 6C 65 4E 61 6D 65 29 2C 38 2C 54 72 75 65 29 20 20 27}
		$s14 = {73 65 74 20 66 73 3D 73 65 72 76 65 72 2E 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 53 63 72 69 70 74 69 6E 67 2E 46 69 6C 65 53 79 73 74 65 6D 4F 62 6A 65 63 74 5C 22 29 20 20 20 27}
		$s16 = {3C 54 49 54 4C 45 3E 45 78 70 64 6F 6F 72 2E 63 6F 6D 20 41 53 50}

	condition:
		2 of them
}

rule webshell_webshells_new_php2
{
	meta:
		description = "Web shells - generated from file php2.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "fbf2e76e6f897f6f42b896c855069276"

	strings:
		$s0 = {3C 3F 70 68 70 20 24 73 3D 40 24 5F 47 45 54 5B 32 5D 3B 69 66 28 6D 64 35 28 24 73 2E 24 73 29 3D 3D}

	condition:
		all of them
}

rule webshell_bypass_iisuser_p
{
	meta:
		description = "Web shells - generated from file bypass-iisuser-p.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "924d294400a64fa888a79316fb3ccd90"

	strings:
		$s0 = {3C 25 45 76 61 6C 28 52 65 71 75 65 73 74 28 63 68 72 28 31 31 32 29 29 29 3A 53 65 74 20 66 73 6F 3D 43 72 65 61 74 65 4F 62 6A 65 63 74}

	condition:
		all of them
}

rule webshell_sig_404super
{
	meta:
		description = "Web shells - generated from file 404super.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "7ed63176226f83d36dce47ce82507b28"

	strings:
		$s4 = {24 69 20 3D 20 70 61 63 6B 28 27 63 2A 27 2C 20 30 78 37 30 2C 20 30 78 36 31 2C 20 39 39 2C 20 31 30 37 29 3B}
		$s6 = {20 20 20 20 27 68 27 20 3D 3E 20 24 69 28 27 48 2A 27 2C 20 27 36 38 37 34 37 34 37 30 33 61 32 66 32 66 36 32 36 63 36 31 36 62 36 39 36 65 32 65 36 34 37 35 36 31 37 30 37 30 32 65 36 33 36 66 36 64 32 66 37 36 33 31 27 29 2C}
		$s7 = {2F 2F 68 74 74 70 3A 2F 2F 72 65 71 75 69 72 65 2E 64 75 61 70 70 2E 63 6F 6D 2F 73 65 73 73 69 6F 6E 2E 70 68 70}
		$s8 = {69 66 28 21 69 73 73 65 74 28 24 5F 53 45 53 53 49 4F 4E 5B 27 74 27 5D 29 29 7B 24 5F 53 45 53 53 49 4F 4E 5B 27 74 27 5D 20 3D 20 24 47 4C 4F 42 41 4C 53 5B 27 66 27 5D 28 24 47 4C 4F 42 41 4C 53 5B 27 68 27 5D 29 3B 7D}
		$s12 = {2F 2F 64 65 66 69 6E 65 28 27 70 61 73 73 27 2C 27 31 32 33 34 35 36 27 29 3B}
		$s13 = {24 47 4C 4F 42 41 4C 53 5B 27 63 27 5D 28 24 47 4C 4F 42 41 4C 53 5B 27 65 27 5D 28 6E 75 6C 6C 2C 20 24 47 4C 4F 42 41 4C 53 5B 27 73 27 5D 28 27 25 73 27 2C 24 47 4C 4F 42 41 4C 53 5B 27 70 27 5D 28 27 48 2A 27 2C 24 5F 53 45 53 53 49 4F}

	condition:
		1 of them
}

rule webshell_webshells_new_JSP
{
	meta:
		description = "Web shells - generated from file JSP.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "495f1a0a4c82f986f4bdf51ae1898ee7"

	strings:
		$s1 = {76 6F 69 64 20 41 41 28 53 74 72 69 6E 67 42 75 66 66 65 72 20 73 62 29 74 68 72 6F 77 73 20 45 78 63 65 70 74 69 6F 6E 7B 46 69 6C 65 20 72 5B 5D 3D 46 69 6C 65 2E 6C 69 73 74 52 6F 6F 74 73 28 29 3B 66 6F 72 28 69 6E 74 20 69 3D 30 3B 69}
		$s5 = {62 77 2E 77 72 69 74 65 28 7A 32 29 3B 62 77 2E 63 6C 6F 73 65 28 29 3B 73 62 2E 61 70 70 65 6E 64 28 5C 22 31 5C 22 29 3B 7D 65 6C 73 65 20 69 66 28 5A 2E 65 71 75 61 6C 73 28 5C 22 45 5C 22 29 29 7B 45 45 28 7A 31 29 3B 73 62 2E 61 70 70}
		$s11 = {69 66 28 5A 2E 65 71 75 61 6C 73 28 5C 22 41 5C 22 29 29 7B 53 74 72 69 6E 67 20 73 3D 6E 65 77 20 46 69 6C 65 28 61 70 70 6C 69 63 61 74 69 6F 6E 2E 67 65 74 52 65 61 6C 50 61 74 68 28 72 65 71 75 65 73 74 2E 67 65 74 52 65 71 75 65 73 74}

	condition:
		1 of them
}

rule webshell_webshell_123
{
	meta:
		description = "Web shells - generated from file webshell-123.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "2782bb170acaed3829ea9a04f0ac7218"

	strings:
		$s0 = {2F 2F 20 57 65 62 20 53 68 65 6C 6C 21 21}
		$s1 = {40 70 72 65 67 5F 72 65 70 6C 61 63 65 28 5C 22 2F 2E 2A 2F 65 5C 22 2C 5C 22 5C 5C 78 36 35 5C 5C 78 37 36 5C 5C 78 36 31 5C 5C 78 36 43 5C 5C 78 32 38 5C 5C 78 36 37 5C 5C 78 37 41 5C 5C 78 36 39 5C 5C 78 36 45 5C 5C 78 36 36 5C 5C 78 36}
		$s3 = {24 64 65 66 61 75 6C 74 5F 63 68 61 72 73 65 74 20 3D 20 5C 22 55 54 46 2D 38 5C 22 3B}
		$s4 = {2F 2F 20 75 72 6C 3A 68 74 74 70 3A 2F 2F 77 77 77 2E 77 65 69 67 6F 6E 67 6B 61 69 2E 63 6F 6D 2F 73 68 65 6C 6C 2F}

	condition:
		2 of them
}

rule webshell_dev_core
{
	meta:
		description = "Web shells - generated from file dev_core.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "55ad9309b006884f660c41e53150fc2e"

	strings:
		$s1 = {69 66 20 28 73 74 72 70 6F 73 28 24 5F 53 45 52 56 45 52 5B 27 48 54 54 50 5F 55 53 45 52 5F 41 47 45 4E 54 27 5D 2C 20 27 45 42 53 44 27 29 20 3D 3D 20 66 61 6C 73 65 29 20 7B}
		$s9 = {73 65 74 63 6F 6F 6B 69 65 28 27 6B 65 79 27 2C 20 24 5F 50 4F 53 54 5B 27 70 77 64 27 5D 2C 20 74 69 6D 65 28 29 20 2B 20 33 36 30 30 20 2A 20 32 34 20 2A 20 33 30 29 3B}
		$s10 = {24 5F 53 45 53 53 49 4F 4E 5B 27 63 6F 64 65 27 5D 20 3D 20 5F 52 45 51 55 45 53 54 28 73 70 72 69 6E 74 66 28 5C 22 25 73 3F 25 73 5C 22 2C 70 61 63 6B 28 5C 22 48 2A 5C 22 2C 27 36 38 37 34}
		$s11 = {69 66 20 28 70 72 65 67 5F 6D 61 74 63 68 28 5C 22 2F 5E 48 54 54 50 5C 5C 2F 5C 5C 64 5C 5C 2E 5C 5C 64 5C 5C 73 28 5B 5C 5C 64 5D 2B 29 5C 5C 73 2E 2A 24 2F 5C 22 2C 20 24 73 74 61 74 75 73 2C 20 24 6D 61 74 63 68 65 73 29 29}
		$s12 = {65 76 61 6C 28 67 7A 75 6E 63 6F 6D 70 72 65 73 73 28 67 7A 75 6E 63 6F 6D 70 72 65 73 73 28 43 72 79 70 74 3A 3A 64 65 63 72 79 70 74 28 24 5F 53 45 53 53 49 4F 4E 5B 27 63 6F 64 65 27 5D 2C 20 24 5F 43}
		$s15 = {69 66 20 28 28 24 66 73 6F 63 6B 20 3D 20 66 73 6F 63 6B 6F 70 65 6E 28 24 75 72 6C 32 5B 27 68 6F 73 74 27 5D 2C 20 38 30 2C 20 24 65 72 72 6E 6F 2C 20 24 65 72 72 73 74 72 2C 20 24 66 73 6F 63 6B 5F 74 69 6D 65 6F 75 74 29 29}

	condition:
		1 of them
}

rule webshell_webshells_new_pHp
{
	meta:
		description = "Web shells - generated from file pHp.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "b0e842bdf83396c3ef8c71ff94e64167"

	strings:
		$s0 = {69 66 28 69 73 5F 72 65 61 64 61 62 6C 65 28 24 70 61 74 68 29 29 20 61 6E 74 69 76 69 72 75 73 28 24 70 61 74 68 2E 27 2F 27 2C 24 65 78 73 2C 24 6D 61 74 63 68 65 73 29 3B}
		$s1 = {27 2F 28 65 76 61 6C 7C 61 73 73 65 72 74 7C 69 6E 63 6C 75 64 65 7C 72 65 71 75 69 72 65 7C 69 6E 63 6C 75 64 65 5C 5C 5F 6F 6E 63 65 7C 72 65 71 75 69 72 65 5C 5C 5F 6F 6E 63 65 7C 61 72 72 61 79 5C 5C 5F 6D 61 70 7C 61 72 72}
		$s13 = {27 2F 28 65 78 65 63 7C 73 68 65 6C 6C 5C 5C 5F 65 78 65 63 7C 73 79 73 74 65 6D 7C 70 61 73 73 74 68 72 75 29 2B 5C 5C 73 2A 5C 5C 28 5C 5C 73 2A 5C 5C 24 5C 5C 5F 28 5C 5C 77 2B 29 5C 5C 5B 28 2E 2A 29 5C 5C 5D 5C 5C 73 2A}
		$s14 = {27 2F 28 69 6E 63 6C 75 64 65 7C 72 65 71 75 69 72 65 7C 69 6E 63 6C 75 64 65 5C 5C 5F 6F 6E 63 65 7C 72 65 71 75 69 72 65 5C 5C 5F 6F 6E 63 65 29 2B 5C 5C 73 2A 5C 5C 28 5C 5C 73 2A 5B 5C 5C 27 7C 5C 5C 5C 22 5D 28 5C 5C 77 2B}
		$s19 = {27 2F 5C 5C 24 5C 5C 5F 28 5C 5C 77 2B 29 28 2E 2A 29 28 65 76 61 6C 7C 61 73 73 65 72 74 7C 69 6E 63 6C 75 64 65 7C 72 65 71 75 69 72 65 7C 69 6E 63 6C 75 64 65 5C 5C 5F 6F 6E 63 65 7C 72 65 71 75 69 72 65 5C 5C 5F 6F 6E 63 65}

	condition:
		1 of them
}

rule webshell_webshells_new_pppp
{
	meta:
		description = "Web shells - generated from file pppp.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "cf01cb6e09ee594545693c5d327bdd50"

	strings:
		$s0 = {4D 61 69 6C 3A 20 63 68 69 6E 65 73 65 40 68 61 63 6B 65 72 6D 61 69 6C 2E 63 6F 6D}
		$s3 = {69 66 28 24 5F 47 45 54 5B 5C 22 68 61 63 6B 65 72 73 5C 22 5D 3D 3D 5C 22 32 62 5C 22 29 7B 69 66 20 28 24 5F 53 45 52 56 45 52 5B 27 52 45 51 55 45 53 54 5F 4D 45 54 48 4F 44 27 5D 20 3D 3D 20 27 50 4F 53 54 27 29 20 7B 20 65 63 68 6F 20}
		$s6 = {53 69 74 65 3A 20 68 74 74 70 3A 2F 2F 62 6C 6F 67 2E 77 65 69 6C 69 2E 6D 65}

	condition:
		1 of them
}

rule webshell_webshells_new_code
{
	meta:
		description = "Web shells - generated from file code.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "a444014c134ff24c0be5a05c02b81a79"

	strings:
		$s1 = {3C 61 20 63 6C 61 73 73 3D 5C 22 68 69 67 68 32 5C 22 20 68 72 65 66 3D 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 3B 3B 3B 5C 22 20 6E 61 6D 65 3D 5C 22 61 63 74 69 6F 6E 3D 73 68 6F 77 26 64 69 72 3D 24 5F 69 70 61 67 65 5F 66 69}
		$s7 = {24 66 69 6C 65 20 3D 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 5C 22 64 69 72 5C 22 5D 29 20 3F 20 75 72 6C 64 65 63 6F 64 65 28 73 65 6C 66 3A 3A 63 6F 6E 76 65 72 74 5F 74 6F 5F 75 74 66 38 28 72 74 72 69 6D 28 24 5F 50 4F}
		$s10 = {69 66 20 28 74 72 75 65 3D 3D 40 6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 5F 46 49 4C 45 53 5B 27 75 73 65 72 66 69 6C 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 73 65 6C 66 3A 3A 63 6F 6E 76 65 72 74 5F}
		$s14 = {50 72 6F 63 65 73 73 65 64 20 69 6E 20 3C 73 70 61 6E 20 69 64 3D 5C 22 72 75 6E 74 69 6D 65 5C 22 3E 3C 2F 73 70 61 6E 3E 20 73 65 63 6F 6E 64 28 73 29 20 7B 67 7A 69 70 7D 20 75 73 61 67 65 3A}
		$s17 = {3C 61 20 68 72 65 66 3D 5C 22 6A 61 76 61 73 63 72 69 70 74 3A 3B 3B 3B 5C 22 20 6E 61 6D 65 3D 5C 22 7B 72 65 74 75 72 6E 5F 6C 69 6E 6B 7D 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 22 66 69 6C 65 70 65 72 6D}

	condition:
		1 of them
}

rule webshell_webshells_new_jspyyy
{
	meta:
		description = "Web shells - generated from file jspyyy.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "b291bf3ccc9dac8b5c7e1739b8fa742e"

	strings:
		$s0 = {3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 69 6F 2E 2A 5C 22 25 3E 3C 25 69 66 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 5C 22 29}

	condition:
		all of them
}

rule webshell_webshells_new_xxxx
{
	meta:
		description = "Web shells - generated from file xxxx.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "5bcba70b2137375225d8eedcde2c0ebb"

	strings:
		$s0 = {3C 3F 70 68 70 20 65 76 61 6C 28 24 5F 50 4F 53 54 5B 31 5D 29 3B 3F 3E 20 20}

	condition:
		all of them
}

rule webshell_webshells_new_JJjsp3
{
	meta:
		description = "Web shells - generated from file JJjsp3.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "949ffee1e07a1269df7c69b9722d293e"

	strings:
		$s0 = {3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E 69 6F 2E 2A 2C 6A 61 76 61 2E 75 74 69 6C 2E 2A 2C 6A 61 76 61 2E 6E 65 74 2E 2A 2C 6A 61 76 61 2E 73 71 6C 2E 2A 2C 6A 61 76 61 2E 74 65 78 74 2E 2A 5C 22 25 3E 3C 25 21 53}

	condition:
		all of them
}

rule webshell_webshells_new_PHP1
{
	meta:
		description = "Web shells - generated from file PHP1.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "14c7281fdaf2ae004ca5fec8753ce3cb"

	strings:
		$s0 = {3C 5B 75 72 6C 3D 6D 61 69 6C 74 6F 3A 3F 40 61 72 72 61 79 5F 6D 61 70 28 24 5F 47 45 54 5B 5D 3F 40 61 72 72 61 79 5F 6D 61 70 28 24 5F 47 45 54 5B 27 66 27 5D 2C 24 5F 47 45 54 5B 2F 75 72 6C 5D 29 3B 3F 3E}
		$s2 = {3A 68 74 74 70 73 3A 2F 2F 66 6F 72 75 6D 2E 39 30 73 65 63 2E 6F 72 67 2F 66 6F 72 75 6D 2E 70 68 70 3F 6D 6F 64 3D 76 69 65 77 74 68 72 65 61 64 26 74 69 64 3D 37 33 31 36}
		$s3 = {40 70 72 65 67 5F 72 65 70 6C 61 63 65 28 5C 22 2F 66 2F 65 5C 22 2C 24 5F 47 45 54 5B 27 75 27 5D 2C 5C 22 66 65 6E 67 6A 69 61 6F 5C 22 29 3B 20}

	condition:
		1 of them
}

rule webshell_webshells_new_JJJsp2
{
	meta:
		description = "Web shells - generated from file JJJsp2.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "5a9fec45236768069c99f0bfd566d754"

	strings:
		$s2 = {51 51 28 63 73 2C 20 7A 31 2C 20 7A 32 2C 20 73 62 2C 7A 32 2E 69 6E 64 65 78 4F 66 28 5C 22 2D 74 6F 3A 5C 22 29 21 3D 2D 31 3F 7A 32 2E 73 75 62 73 74 72 69 6E 67 28 7A 32 2E 69 6E 64 65 78 4F 66 28 5C 22 2D 74 6F 3A 5C 22 29 2B 34 2C 7A}
		$s8 = {73 62 2E 61 70 70 65 6E 64 28 6C 5B 69 5D 2E 67 65 74 4E 61 6D 65 28 29 20 2B 20 5C 22 2F 5C 5C 74 5C 22 20 2B 20 73 54 20 2B 20 5C 22 5C 5C 74 5C 22 20 2B 20 6C 5B 69 5D 2E 6C 65 6E 67 74 68 28 29 2B 20 5C 22 5C 5C 74 5C 22 20 2B 20 73 51}
		$s10 = {52 65 73 75 6C 74 53 65 74 20 72 20 3D 20 73 2E 69 6E 64 65 78 4F 66 28 5C 22 6A 64 62 63 3A 6F 72 61 63 6C 65 5C 22 29 21 3D 2D 31 3F 63 2E 67 65 74 4D 65 74 61 44 61 74 61 28 29}
		$s11 = {72 65 74 75 72 6E 20 44 72 69 76 65 72 4D 61 6E 61 67 65 72 2E 67 65 74 43 6F 6E 6E 65 63 74 69 6F 6E 28 78 5B 31 5D 2E 74 72 69 6D 28 29 2B 5C 22 3A 5C 22 2B 78 5B 34 5D 2C 78 5B 32 5D 2E 65 71 75 61 6C 73 49 67 6E 6F 72 65 43 61 73 65 28}

	condition:
		1 of them
}

rule webshell_webshells_new_radhat
{
	meta:
		description = "Web shells - generated from file radhat.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "72cb5ef226834ed791144abaa0acdfd4"

	strings:
		$s1 = {73 6F 64 3D 41 72 72 61 79 28 5C 22 44 5C 22 2C 5C 22 37 5C 22 2C 5C 22 53}

	condition:
		all of them
}

rule webshell_webshells_new_asp1
{
	meta:
		description = "Web shells - generated from file asp1.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "b63e708cd58ae1ec85cf784060b69cad"

	strings:
		$s0 = {20 68 74 74 70 3A 2F 2F 77 77 77 2E 62 61 69 64 75 2E 63 6F 6D 2F 66 75 63 6B 2E 61 73 70 3F 61 3D 29 30 28 74 73 65 75 71 65 72 25 32 30 6C 61 76 65 20}
		$s2 = {20 3C 25 20 61 3D 72 65 71 75 65 73 74 28 63 68 72 28 39 37 29 29 20 45 78 65 63 75 74 65 47 6C 6F 62 61 6C 28 53 74 72 52 65 76 65 72 73 65 28 61 29 29 20 25 3E}

	condition:
		1 of them
}

rule webshell_webshells_new_php6
{
	meta:
		description = "Web shells - generated from file php6.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "ea75280224a735f1e445d244acdfeb7b"

	strings:
		$s1 = {61 72 72 61 79 5F 6D 61 70 28 5C 22 61 73 78 37 33 65 72 74 5C 22 2C 28 61 72}
		$s3 = {70 72 65 67 5F 72 65 70 6C 61 63 65 28 5C 22 2F 5B 65 72 72 6F 72 70 61 67 65 5D 2F 65 5C 22 2C 24 70 61 67 65 2C 5C 22 73 61 66 74 5C 22 29 3B}
		$s4 = {73 68 65 6C 6C 2E 70 68 70 3F 71 69 64 3D 7A 78 65 78 70 20 20}

	condition:
		1 of them
}

rule webshell_webshells_new_xxx
{
	meta:
		description = "Web shells - generated from file xxx.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "0e71428fe68b39b70adb6aeedf260ca0"

	strings:
		$s3 = {3C 3F 70 68 70 20 61 72 72 61 79 5F 6D 61 70 28 5C 22 61 73 73 5C 5C 78 36 35 72 74 5C 22 2C 28 61 72 72 61 79 29 24 5F 52 45 51 55 45 53 54 5B 27 65 78 70 64 6F 6F 72 27 5D 29 3B 3F 3E}

	condition:
		all of them
}

rule webshell_GetPostpHp
{
	meta:
		description = "Web shells - generated from file GetPostpHp.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "20ede5b8182d952728d594e6f2bb5c76"

	strings:
		$s0 = {3C 3F 70 68 70 20 65 76 61 6C 28 73 74 72 5F 72 6F 74 31 33 28 27 72 69 6E 79 28 24 5F 43 42 46 47 5B 63 6E 74 72 5D 29 3B 27 29 29 3B 3F 3E}

	condition:
		all of them
}

rule webshell_webshells_new_php5
{
	meta:
		description = "Web shells - generated from file php5.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "cf2ab009cbd2576a806bfefb74906fdf"

	strings:
		$s0 = {3C 3F 24 5F 75 55 3D 63 68 72 28 39 39 29 2E 63 68 72 28 31 30 34 29 2E 63 68 72 28 31 31 34 29 3B 24 5F 63 43 3D 24 5F 75 55 28 31 30 31 29 2E 24 5F 75 55 28 31 31 38 29 2E 24 5F 75 55 28 39 37 29 2E 24 5F 75 55 28 31 30 38 29 2E 24 5F 75}

	condition:
		all of them
}

rule webshell_webshells_new_PHP
{
	meta:
		description = "Web shells - generated from file PHP.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "a524e7ae8d71e37d2fd3e5fbdab405ea"

	strings:
		$s1 = {65 63 68 6F 20 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 62 6C 75 65 3E 45 72 72 6F 72 21 3C 2F 66 6F 6E 74 3E 5C 22 3B}
		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 73 69 7A 65 3D 36 31 20 6E 61 6D 65 3D 5C 22 66 5C 22 20 76 61 6C 75 65 3D 27 3C 3F 70 68 70 20 65 63 68 6F 20 24 5F 53 45 52 56 45 52 5B 5C 22 53 43 52 49 50 54 5F 46 49 4C 45}
		$s5 = {20 2D 20 45 78 70 44 6F 6F 72 2E 63 6F 6D 3C 2F 74 69 74 6C 65 3E}
		$s10 = {24 66 3D 66 6F 70 65 6E 28 24 5F 50 4F 53 54 5B 5C 22 66 5C 22 5D 2C 5C 22 77 5C 22 29 3B}
		$s12 = {3C 74 65 78 74 61 72 65 61 20 6E 61 6D 65 3D 5C 22 63 5C 22 20 63 6F 6C 73 3D 36 30 20 72 6F 77 73 3D 31 35 3E 3C 2F 74 65 78 74 61 72 65 61 3E 3C 62 72 3E}

	condition:
		1 of them
}

rule webshell_webshells_new_Asp
{
	meta:
		description = "Web shells - generated from file Asp.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "32c87744ea404d0ea0debd55915010b7"

	strings:
		$s1 = {45 78 65 63 75 74 65 20 4D 6F 72 66 69 43 6F 64 65 72 28 5C 22 29 2F 2A 2F 7A 2F 2A 2F 28 74 73 65 75 71 65 72 20 6C 61 76 65 5C 22 29}
		$s2 = {46 75 6E 63 74 69 6F 6E 20 4D 6F 72 66 69 43 6F 64 65 72 28 43 6F 64 65 29}
		$s3 = {4D 6F 72 66 69 43 6F 64 65 72 3D 52 65 70 6C 61 63 65 28 52 65 70 6C 61 63 65 28 53 74 72 52 65 76 65 72 73 65 28 43 6F 64 65 29 2C 5C 22 2F 2A 2F 5C 22 2C 5C 22 5C 22 5C 22 5C 22 29 2C 5C 22 5C 5C 2A 5C 5C 5C 22 2C 76 62 43 72 6C 66 29}

	condition:
		1 of them
}

rule perlbot_pl
{
	meta:
		description = "Semi-Auto-generated  - file perlbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "7e4deb9884ffffa5d82c22f8dc533a45"

	strings:
		$s0 = {6D 79 20 40 61 64 6D 73 3D 28 5C 22 4B 65 6C 73 65 72 69 66 69 63 5C 22 2C 5C 22 50 75 6E 61 5C 22 2C 5C 22 6E 6F 64 33 32 5C 22 29}
		$s1 = {23 41 63 65 73 73 6F 20 61 20 53 68 65 6C 20 2D 20 31 20 4F 4E 20 30 20 4F 46 46}

	condition:
		1 of them
}

rule php_backdoor_php
{
	meta:
		description = "Semi-Auto-generated  - file php-backdoor.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"

	strings:
		$s0 = {68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 20 20 20 32 30 30 36}
		$s1 = {6F 72 20 68 74 74 70 3A 2F 2F 3C 3F 20 65 63 68 6F 20 24 53 45 52 56 45 52 5F 4E 41 4D 45 2E 24 52 45 51 55 45 53 54 5F 55 52 49 3B 20 3F 3E 3F 64 3D 63 3A 2F 77 69 6E 64 6F 77 73 20 6F 6E 20 77 69 6E}
		$s3 = {63 6F 64 65 64 20 62 79 20 7A 30 6D 62 69 65}

	condition:
		1 of them
}

rule Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_php
{
	meta:
		description = "Semi-Auto-generated  - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"

	strings:
		$s0 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 63 61 74 20 2F 76 61 72 2F 63 70 61 6E 65 6C 2F 61 63 63 6F 75 6E 74 69 6E 67 2E 6C 6F 67 5C 22 3E 2F 76 61 72 2F 63 70 61 6E 65 6C 2F 61 63 63 6F 75 6E 74 69 6E 67 2E 6C 6F 67 3C 2F 6F 70 74}
		$s1 = {4C 69 7A 30 7A 69 4D 20 50 72 69 76 61 74 65 20 53 61 66 65 20 4D 6F 64 65 20 43 6F 6D 6D 61 6E 64 20 45 78 65 63 75 72 69 74 6F 6E 20 42 79 70 61 73 73}
		$s2 = {65 63 68 6F 20 5C 22 3C 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 4B 69 6D 69 6D 20 42 65 6E 20 3A 3D 29 3C 2F 66 6F 6E 74 3E 3C 2F 62 3E 3A 24 75 69 64 3C 62 72 3E 5C 22 3B}

	condition:
		1 of them
}

rule Nshell__1__php_php
{
	meta:
		description = "Semi-Auto-generated  - file Nshell (1).php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "973fc89694097a41e684b43a21b1b099"

	strings:
		$s0 = {65 63 68 6F 20 5C 22 43 6F 6D 6D 61 6E 64 20 3A 20 3C 49 4E 50 55 54 20 54 59 50 45 3D 74 65 78 74 20 4E 41 4D 45 3D 63 6D 64 20 76 61 6C 75 65 3D 5C 22 2E 40 73 74 72 69 70 73 6C 61 73 68 65 73 28 68 74 6D 6C 65 6E 74 69 74 69 65 73 28 24}
		$s1 = {69 66 28 21 24 77 68 6F 61 6D 69 29 24 77 68 6F 61 6D 69 3D 65 78 65 63 28 5C 22 77 68 6F 61 6D 69 5C 22 29 3B 20 65 63 68 6F 20 5C 22 77 68 6F 61 6D 69 20 3A 5C 22 2E 24 77 68 6F 61 6D 69 2E 5C 22 3C 62 72 3E 5C 22 3B}

	condition:
		1 of them
}

rule shankar_php_php
{
	meta:
		description = "Semi-Auto-generated  - file shankar.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "6eb9db6a3974e511b7951b8f7e7136bb"

	strings:
		$sAuthor = {53 68 41 6E 4B 61 52}
		$s0 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 63 68 65 63 6B 62 6F 78 20 6E 61 6D 65 3D 27 64 64 27 20 5C 22 2E 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 64 64 27 5D 29 3F 27 63 68 65 63 6B 65 64 27 3A 27 27 29 2E 5C 22 3E 44 42 3C 69 6E 70 75 74}
		$s3 = {53 68 6F 77 3C 69 6E 70 75 74 20 74 79 70 65 3D 74 65 78 74 20 73 69 7A 65 3D 35 20 76 61 6C 75 65 3D 5C 22 2E 28 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 62 72 5F 73 74 27 5D 29 20 26 26 20 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 62}

	condition:
		1 of ($s*) and $sAuthor
}

rule Casus15_php_php
{
	meta:
		description = "Semi-Auto-generated  - file Casus15.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5e2ede2d1c4fa1fcc3cbfe0c005d7b13"

	strings:
		$s0 = {63 6F 70 79 20 28 20 24 64 6F 73 79 61 5F 67 6F 6E 64 65 72 32 2C 20 5C 22 24 64 69 72 2F 24 64 6F 73 79 61 5F 67 6F 6E 64 65 72 32 5F 6E 61 6D 65 5C 22 29 20 3F 20 70 72 69 6E 74 28 5C 22 24 64 6F 73 79 61 5F 67 6F 6E 64 65 72 32 5F 6E 61}
		$s2 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 66 6F 6E 74 20 73 69 7A 65 3D 27 24 73 61 79 69 27 20 63 6F 6C 6F 72 3D 27 23 46 46 46 46 46 46 27 3E 48 41 43 4B 4C 45 52 49 4E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 27 23 30 30 38 30 30 30 27}
		$s3 = {76 61 6C 75 65 3D 27 43 61 6C 69 73 74 69 72 6D 61 6B 20 69 73 74 65 64 69 67 69 6E 69 7A 20}

	condition:
		1 of them
}

rule small_php_php
{
	meta:
		description = "Semi-Auto-generated  - file small.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "fcee6226d09d150bfa5f103bee61fbde"

	strings:
		$s1 = {24 70 61 73 73 3D 27 61 62 63 64 65 66 31 32 33 34 35 36 37 38 39 30 61 62 63 64 65 66 31 32 33 34 35 36 37 38 39 30 27 3B}
		$s2 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27 46 4A 7A 48 6B 71 50 61 74 6B 55 2F 35 35 30 49 47 6E 6A 58 78 48 76 76 36 62 7A 41 65 30 69 45 35 2B 73 76 46 56 47 74 4B 71 58 4D 5A 71 30 35 78 31}
		$s4 = {40 69 6E 69 5F 73 65 74 28 27 65 72 72 6F 72 5F 6C 6F 67 27 2C 4E 55 4C 4C 29 3B}

	condition:
		2 of them
}

rule shellbot_pl
{
	meta:
		description = "Semi-Auto-generated  - file shellbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b2a883bc3c03a35cfd020dd2ace4bab8"

	strings:
		$s0 = {53 68 65 6C 6C 42 4F 54}
		$s1 = {50 61 63 6B 74 73 47 72 30 75 70}
		$s2 = {43 6F 52 70 4F 72 41 74 49 6F 4E}
		$s3 = {23 20 53 65 72 76 69 64 6F 72 20 64 65 20 69 72 63 20 71 75 65 20 76 61 69 20 73 65 72 20 75 73 61 64 6F 20}
		$s4 = {2F 5E 63 74 63 70 66 6C 6F 6F 64 5C 5C 73 2B 28 5C 5C 64 2B 29 5C 5C 73 2B 28 5C 5C 53 2B 29}

	condition:
		2 of them
}

rule fuckphpshell_php
{
	meta:
		description = "Semi-Auto-generated  - file fuckphpshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "554e50c1265bb0934fcc8247ec3b9052"

	strings:
		$s0 = {24 73 75 63 63 20 3D 20 5C 22 57 61 72 6E 69 6E 67 21 20}
		$s1 = {44 6F 6E 60 74 20 62 65 20 73 74 75 70 69 64 20 2E 2E 20 74 68 69 73 20 69 73 20 61 20 70 72 69 76 33 20 73 65 72 76 65 72 2C 20 73 6F 20 74 61 6B 65 20 65 78 74 72 61 20 63 61 72 65 21}
		$s2 = {5C 5C 2A 3D 2D 2D 20 4D 45 4D 42 45 52 53 20 41 52 45 41 20 2D 2D 3D 2A 2F}
		$s3 = {70 72 65 67 5F 6D 61 74 63 68 28 27 2F 28 5C 5C 6E 5B 5E 5C 5C 6E 5D 2A 29 7B 27 20 2E 20 24 63 61 63 68 65 5F 6C 69 6E 65 73 20 2E 20 27 7D 24 2F 27 2C 20 24 5F 53 45 53 53 49 4F 4E 5B 27 6F}

	condition:
		2 of them
}

rule ngh_php_php
{
	meta:
		description = "Semi-Auto-generated  - file ngh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c372b725419cdfd3f8a6371cfeebc2fd"

	strings:
		$s0 = {43 72 34 73 68 5F 61 6B 61 5F 52 4B 4C}
		$s1 = {4E 47 48 20 65 64 69 74 69 6F 6E}
		$s2 = {2F 2A 20 63 6F 6E 6E 65 63 74 62 61 63 6B 2D 62 61 63 6B 64 6F 6F 72 20 6F 6E 20 70 65 72 6C}
		$s3 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 3C 3F 3D 24 73 63 72 69 70 74 3F 3E 3F 61 63 74 3D 62 69 6E 64 73 68 65 6C 6C 20 6D 65 74 68 6F 64 3D 50 4F 53 54 3E}
		$s4 = {24 6C 6F 67 6F 20 3D 20 5C 22 52 30 6C 47 4F 44 6C 68 4D 41 41 77 41 4F 59 41 41 41 41 41 41 50 2F 2F 2F 2F 72}

	condition:
		1 of them
}

rule jsp_reverse_jsp
{
	meta:
		description = "Semi-Auto-generated  - file jsp-reverse.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8b0e6779f25a17f0ffb3df14122ba594"

	strings:
		$s0 = {2F 2F 20 62 61 63 6B 64 6F 6F 72 2E 6A 73 70}
		$s1 = {4A 53 50 20 42 61 63 6B 64 6F 6F 72 20 52 65 76 65 72 73 65 20 53 68 65 6C 6C}
		$s2 = {68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67}

	condition:
		2 of them
}

rule Tool_asp
{
	meta:
		description = "Semi-Auto-generated  - file Tool.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8febea6ca6051ae5e2ad4c78f4b9c1f2"

	strings:
		$s0 = {6D 61 69 6C 74 6F 3A 72 68 66 61 63 74 6F 72 40 61 6E 74 69 73 6F 63 69 61 6C 2E 63 6F 6D}
		$s2 = {3F 72 61 69 7A 3D 72 6F 6F 74}
		$s3 = {44 49 47 4F 20 43 4F 52 52 4F 4D 50 49 44 4F 3C 42 52 3E 43 4F 52 52 55 50 54 20 43 4F 44 45}
		$s4 = {6B 65 79 20 3D 20 5C 22 35 44 43 41 44 41 43 31 39 30 32 45 35 39 46 37 32 37 33 45 31 39 30 32 45 35 41 44 38 34 31 34 42 31 39 30 32 45 35 41 42 46 33 45 36 36 31 39 30 32 45 35 42 35 35 34 46 43 34 31 39 30 32 45 35 33 32 30 35 43 41 30}

	condition:
		2 of them
}

rule NT_Addy_asp
{
	meta:
		description = "Semi-Auto-generated  - file NT Addy.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2e0d1bae844c9a8e6e351297d77a1fec"

	strings:
		$s0 = {4E 54 44 61 64 64 79 20 76 31 2E 39 20 62 79 20 6F 62 7A 65 72 76 65 20 6F 66 20 66 75 78 30 72 20 69 6E 63}
		$s2 = {3C 45 52 52 4F 52 3A 20 54 48 49 53 20 49 53 20 4E 4F 54 20 41 20 54 45 58 54 20 46 49 4C 45 3E}
		$s4 = {52 41 57 20 44 2E 4F 2E 53 2E 20 43 4F 4D 4D 41 4E 44 20 49 4E 54 45 52 46 41 43 45}

	condition:
		1 of them
}

rule SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php
{
	meta:
		description = "Semi-Auto-generated  - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "089ff24d978aeff2b4b2869f0c7d38a3"

	strings:
		$s0 = {53 69 6D 41 74 74 61 63 6B 65 72 20 2D 20 56 72 73 69 6F 6E 20 3A 20 31 2E 30 2E 30 20 2D 20 70 72 69 76 38 20 34 20 4D 79 20 66 72 69 65 6E 64}
		$s3 = {20 66 70 75 74 73 20 28 24 66 70 20 2C 5C 22 5C 5C 6E 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 5C 5C 6E 57 65 6C 63 6F 6D 65 20 54 30 20 53 69 6D}
		$s4 = {65 63 68 6F 20 5C 22 3C 61 20 74 61 72 67 65 74 3D 27 5F 62 6C 61 6E 6B 27 20 68 72 65 66 3D 27 3F 69 64 3D 66 6D 26 66 65 64 69 74 3D 24 64 69 72 24 66 69 6C 65 27 3E 3C 73 70 61 6E 20 73 74 79 6C 65 3D 27 74 65 78 74 2D 64 65 63 6F 72 61}

	condition:
		1 of them
}

rule RemExp_asp
{
	meta:
		description = "Semi-Auto-generated  - file RemExp.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "aa1d8491f4e2894dbdb91eec1abc2244"

	strings:
		$s0 = {3C 74 69 74 6C 65 3E 52 65 6D 6F 74 65 20 45 78 70 6C 6F 72 65 72 3C 2F 74 69 74 6C 65 3E}
		$s3 = {20 46 53 4F 2E 43 6F 70 79 46 69 6C 65 20 52 65 71 75 65 73 74 2E 51 75 65 72 79 53 74 72 69 6E 67 28 5C 22 46 6F 6C 64 65 72 50 61 74 68 5C 22 29 20 26 20 52 65 71 75 65 73 74 2E 51 75 65 72 79 53 74 72 69 6E 67 28 5C 22 43 6F 70 79 46 69}
		$s4 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 74 69 74 6C 65 3D 5C 22 3C 25 3D 46 69 6C 65 2E 4E 61 6D 65 25 3E 5C 22 3E 20 3C 61 20 68 72 65 66 3D 20 5C 22 73 68 6F 77 63 6F 64 65 2E 61 73 70 3F 66}

	condition:
		2 of them
}

rule phvayvv_php_php
{
	meta:
		description = "Semi-Auto-generated  - file phvayvv.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "35fb37f3c806718545d97c6559abd262"

	strings:
		$s0 = {7B 6D 6B 64 69 72 28 5C 22 24 64 69 7A 69 6E 2F 24 64 75 7A 65 6E 78 32 5C 22 2C 37 37 37 29}
		$s1 = {24 62 61 67 6C 61 6E 3D 66 6F 70 65 6E 28 24 64 75 7A 6B 61 79 64 65 74 2C 27 77 27 29 3B}
		$s2 = {50 48 56 61 79 76 20 31 2E 30}

	condition:
		1 of them
}

rule klasvayv_asp
{
	meta:
		description = "Semi-Auto-generated  - file klasvayv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b3e64bf8462fc3d008a3d1012da64ef"

	strings:
		$s1 = {73 65 74 20 61 6B 74 69 66 6B 6C 61 73 3D 72 65 71 75 65 73 74 2E 71 75 65 72 79 73 74 72 69 6E 67 28 5C 22 61 6B 74 69 66 6B 6C 61 73 5C 22 29}
		$s2 = {61 63 74 69 6F 6E 3D 5C 22 6B 6C 61 73 76 61 79 76 2E 61 73 70 3F 6B 6C 61 73 6F 72 61 63 3D 31 26 61 6B 74 69 66 6B 6C 61 73 3D 3C 25 3D 61 6B 74 69 66 6B 6C 61 73 25 3E 26 6B 6C 61 73 3D 3C 25 3D 61 6B 74 69 66 6B 6C 61 73 25 3E}
		$s3 = {3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 38 35 38 35 38 35 5C 22 3E 77 77 77 2E 61 76 65 6E 74 67 72 75 70 2E 6E 65 74}
		$s4 = {73 74 79 6C 65 3D 5C 22 42 41 43 4B 47 52 4F 55 4E 44 2D 43 4F 4C 4F 52 3A 20 23 39 35 42 34 43 43 3B 20 42 4F 52 44 45 52 2D 42 4F 54 54 4F 4D 3A 20 23 30 30 30 30 30 30 20 31 70 78 20 69 6E 73 65 74 3B 20 42 4F 52 44 45 52 2D 4C 45 46 54}

	condition:
		1 of them
}

rule r57shell_php_php
{
	meta:
		description = "Semi-Auto-generated  - file r57shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d28445de424594a5f14d0fe2a7c4e94f"

	strings:
		$s0 = {72 35 37 73 68 65 6C 6C}
		$s1 = {20 65 6C 73 65 20 69 66 20 28 24 48 54 54 50 5F 50 4F 53 54 5F 56 41 52 53 5B 27 77 69 74 68 27 5D 20 3D 3D 20 5C 22 6C 79 6E 78 5C 22 29 20 7B 20 24 48 54 54 50 5F 50 4F 53 54 5F 56 41 52 53 5B 27 63 6D 64 27 5D 3D 20 5C 22 6C 79 6E 78 20}
		$s2 = {52 75 73 48 20 73 65 63 75 72 69 74 79 20 74 65 61 6D}
		$s3 = {27 72 75 5F 74 65 78 74 31 32 27 20 3D 3E 20 27 62 61 63 6B 2D 63 6F 6E 6E 65 63 74}

	condition:
		1 of them
}

rule rst_sql_php_php
{
	meta:
		description = "Semi-Auto-generated  - file rst_sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0961641a4ab2b8cb4d2beca593a92010"

	strings:
		$s0 = {43 3A 5C 5C 74 6D 70 5C 5C 64 75 6D 70 5F}
		$s1 = {52 53 54 20 4D 79 53 51 4C}
		$s2 = {68 74 74 70 3A 2F 2F 72 73 74 2E 76 6F 69 64 2E 72 75}
		$s3 = {24 73 74 5F 66 6F 72 6D 5F 62 67 3D 27 52 30 6C 47 4F 44 6C 68 43 51 41 4A 41 49 41 41 41 4F 66 6F 36 75 37 77 38 79 48 35 42 41 41 41 41 41 41 41 4C 41 41 41 41 41 41 4A 41 41 6B 41 41 41 49 50 6A 41 4F 6E 75 4A 66 4E 48 4A 68 30 71 74 66 77 30 6C 63 56 41 44 73 3D 27 3B}

	condition:
		2 of them
}

rule wh_bindshell_py
{
	meta:
		description = "Semi-Auto-generated  - file wh_bindshell.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "fab20902862736e24aaae275af5e049c"

	strings:
		$s0 = {23 55 73 65 3A 20 70 79 74 68 6F 6E 20 77 68 5F 62 69 6E 64 73 68 65 6C 6C 2E 70 79 20 5B 70 6F 72 74 5D 20 5B 70 61 73 73 77 6F 72 64 5D}
		$s2 = {70 79 74 68 6F 6E 20 2D 63 5C 22 69 6D 70 6F 72 74 20 6D 64 35 3B 78 3D 6D 64 35 2E 6E 65 77 28 27 79 6F 75 5F 70 61 73 73 77 6F 72 64 27 29 3B 70 72 69 6E 74 20 78 2E 68 65 78 64 69 67 65 73 74 28 29 5C 22}
		$s3 = {23 62 75 67 7A 3A 20 63 74 72 6C 2B 63 20 65 74 63 20 3D 73 63 72 69 70 74 20 73 74 6F 70 65 64 3D}

	condition:
		1 of them
}

rule lurm_safemod_on_cgi
{
	meta:
		description = "Semi-Auto-generated  - file lurm_safemod_on.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5ea4f901ce1abdf20870c214b3231db3"

	strings:
		$s0 = {4E 65 74 77 6F 72 6B 20 73 65 63 75 72 69 74 79 20 74 65 61 6D 20 3A 3A 20 43 47 49 20 53 68 65 6C 6C}
		$s1 = {23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 3C 3C 4B 4F 4E 45 43 3E 3E 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23}
		$s2 = {23 23 69 66 20 28 21 64 65 66 69 6E 65 64 24 70 61 72 61 6D 7B 70 77 64 7D 29 7B 24 70 61 72 61 6D 7B 70 77 64 7D 3D 27 45 6E 74 65 72 5F 50 61 73 73 77 6F 72 64 27 7D 3B 23 23}

	condition:
		1 of them
}

rule c99madshell_v2_0_php_php
{
	meta:
		description = "Semi-Auto-generated  - file c99madshell_v2.0.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d27292895da9afa5b60b9d3014f39294"

	strings:
		$s2 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27 48 4A 33 48 6B 71 4E 51 45 6B 55 2F 5A 7A 71 43 42 64 34 74 38 56 34 59 41 51 49 32 45 33 6A 76 50 56 38 2F 31 47 77 36 6F 72 73 56 46 4C 79 58 65 66}

	condition:
		all of them
}

rule backupsql_php_often_with_c99shell
{
	meta:
		description = "Semi-Auto-generated  - file backupsql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ab1a06ab1a1fe94e3f3b7f80eedbc12f"

	strings:
		$s2 = {2F 2F 24 6D 65 73 73 61 67 65 2E 3D 20 5C 22 2D 2D 7B 24 6D 69 6D 65 5F 62 6F 75 6E 64 61 72 79 7D 5C 5C 6E 5C 22 20 2E 5C 22 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 7B 24 66 69 6C 65 61 74 74 5F 74 79 70 65 7D 3B 5C 5C 6E 5C 22 20 2E}
		$s4 = {24 66 74 70 63 6F 6E 6E 65 63 74 20 3D 20 5C 22 6E 63 66 74 70 70 75 74 20 2D 75 20 24 66 74 70 5F 75 73 65 72 5F 6E 61 6D 65 20 2D 70 20 24 66 74 70 5F 75 73 65 72 5F 70 61 73 73 20 2D 64 20 64 65 62 73 65 6E 64 65 72 5F 66 74 70 6C 6F 67}

	condition:
		all of them
}

rule uploader_php_php
{
	meta:
		description = "Semi-Auto-generated  - file uploader.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0b53b67bb3b004a8681e1458dd1895d0"

	strings:
		$s2 = {6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 75 73 65 72 66 69 6C 65 2C 20 5C 22 65 6E 74 72 69 6B 61 2E 70 68 70 5C 22 29 3B 20}
		$s3 = {53 65 6E 64 20 74 68 69 73 20 66 69 6C 65 3A 20 3C 49 4E 50 55 54 20 4E 41 4D 45 3D 5C 22 75 73 65 72 66 69 6C 65 5C 22 20 54 59 50 45 3D 5C 22 66 69 6C 65 5C 22 3E}
		$s4 = {3C 49 4E 50 55 54 20 54 59 50 45 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 4D 41 58 5F 46 49 4C 45 5F 53 49 5A 45 5C 22 20 76 61 6C 75 65 3D 5C 22 31 30 30 30 30 30 5C 22 3E}

	condition:
		2 of them
}

rule telnet_pl
{
	meta:
		description = "Semi-Auto-generated  - file telnet.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "dd9dba14383064e219e29396e242c1ec"

	strings:
		$s0 = {57 20 41 20 52 20 4E 20 49 20 4E 20 47 3A 20 50 72 69 76 61 74 65 20 53 65 72 76 65 72}
		$s2 = {24 4D 65 73 73 61 67 65 20 3D 20 71 24 3C 70 72 65 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 36 36 39 39 39 39 5C 22 3E 20 5F 5F 5F 5F 5F 20 20 5F 5F 5F 5F 5F 20 20 5F 5F 5F 5F 5F 20 20 20 20 20 20 20 20 20 20 5F 5F 5F 5F 5F 20 20 20}

	condition:
		all of them
}

rule w3d_php_php
{
	meta:
		description = "Semi-Auto-generated  - file w3d.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "987f66b29bfb209a0b4f097f84f57c3b"

	strings:
		$s0 = {57 33 44 20 53 68 65 6C 6C}
		$s1 = {42 79 3A 20 57 61 72 70 62 6F 79}
		$s2 = {4E 6F 20 51 75 65 72 79 20 45 78 65 63 75 74 65 64}

	condition:
		2 of them
}

rule WebShell_cgi
{
	meta:
		description = "Semi-Auto-generated  - file WebShell.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "bc486c2e00b5fc3e4e783557a2441e6f"

	strings:
		$s0 = {57 65 62 53 68 65 6C 6C 2E 63 67 69}
		$s2 = {3C 74 64 3E 3C 63 6F 64 65 20 63 6C 61 73 73 3D 5C 22 65 6E 74 72 79 2D 5B 25 20 69 66 20 65 6E 74 72 79 2E 61 6C 6C 5F 72 69 67 68 74 73 20 25 5D 6D 69 6E 65 5B 25 20 65 6C 73 65}

	condition:
		all of them
}

rule WinX_Shell_html
{
	meta:
		description = "Semi-Auto-generated  - file WinX Shell.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "17ab5086aef89d4951fe9b7c7a561dda"

	strings:
		$s0 = {57 69 6E 58 20 53 68 65 6C 6C}
		$s1 = {43 72 65 61 74 65 64 20 62 79 20 67 72 65 65 6E 77 6F 6F 64 20 66 72 6F 6D 20 6E 35 37}
		$s2 = {3C 74 64 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 5C 5C 22 23 39 39 30 30 30 30 5C 5C 5C 22 3E 57 69 6E 20 44 69 72 3A 3C 2F 66 6F 6E 74 3E 3C 2F 74 64 3E}

	condition:
		2 of them
}

rule Dx_php_php
{
	meta:
		description = "Semi-Auto-generated  - file Dx.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9cfe372d49fe8bf2fac8e1c534153d9b"

	strings:
		$s0 = {70 72 69 6E 74 20 5C 22 5C 5C 6E 5C 22 2E 27 54 69 70 3A 20 74 6F 20 76 69 65 77 20 74 68 65 20 66 69 6C 65 20 5C 22 61 73 20 69 73 5C 22 20 2D 20 6F 70 65 6E 20 74 68 65 20 70 61 67 65 20 69 6E 20 3C 61 20 68 72 65 66 3D 5C 22 27 2E 44 78}
		$s2 = {24 44 45 46 5F 50 4F 52 54 53 3D 61 72 72 61 79 20 28 31 3D 3E 27 74 63 70 6D 75 78 20 28 54 43 50 20 50 6F 72 74 20 53 65 72 76 69 63 65 20 4D 75 6C 74 69 70 6C 65 78 65 72 29 27 2C 32 3D 3E 27 4D 61 6E 61 67 65 6D 65 6E 74 20 55 74 69 6C}
		$s3 = {24 72 61 34 34 20 20 3D 20 72 61 6E 64 28 31 2C 39 39 39 39 39 29 3B 24 73 6A 39 38 20 3D 20 5C 22 73 68 2D 24 72 61 34 34 5C 22 3B 24 6D 6C 20 3D 20 5C 22 24 73 64 39 38 5C 22 3B 24 61 35 20 3D 20 24 5F 53 45 52 56 45 52 5B 27 48 54 54 50}

	condition:
		1 of them
}

rule csh_php_php
{
	meta:
		description = "Semi-Auto-generated  - file csh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "194a9d3f3eac8bc56d9a7c55c016af96"

	strings:
		$s0 = {2E 3A 3A 5B 63 30 64 65 72 7A 5D 3A 3A 2E 20 77 65 62 2D 73 68 65 6C 6C}
		$s1 = {68 74 74 70 3A 2F 2F 63 30 64 65 72 7A 2E 6F 72 67 2E 75 61}
		$s2 = {76 69 6E 74 32 31 68 40 63 30 64 65 72 7A 2E 6F 72 67 2E 75 61}
		$s3 = {24 6E 61 6D 65 3D 27 36 33 61 39 66 30 65 61 37 62 62 39 38 30 35 30 37 39 36 62 36 34 39 65 38 35 34 38 31 38 34 35 27 3B 2F 2F 72 6F 6F 74}

	condition:
		1 of them
}

rule pHpINJ_php_php
{
	meta:
		description = "Semi-Auto-generated  - file pHpINJ.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d7a4b0df45d34888d5a09f745e85733f"

	strings:
		$s1 = {4E 65 77 73 20 52 65 6D 6F 74 65 20 50 48 50 20 53 68 65 6C 6C 20 49 6E 6A 65 63 74 69 6F 6E}
		$s3 = {50 68 70 20 53 68 65 6C 6C 20 3C 62 72 20 2F 3E}
		$s4 = {3C 69 6E 70 75 74 20 74 79 70 65 20 3D 20 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 20 3D 20 5C 22 75 72 6C 5C 22 20 76 61 6C 75 65 20 3D 20 5C 22}

	condition:
		2 of them
}

rule sig_2008_php_php
{
	meta:
		description = "Semi-Auto-generated  - file 2008.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "3e4ba470d4c38765e4b16ed930facf2c"

	strings:
		$s0 = {43 6F 64 7A 20 62 79 20 61 6E 67 65 6C 28 34 6E 67 65 6C 29}
		$s1 = {57 65 62 3A 20 68 74 74 70 3A 2F 2F 77 77 77 2E 34 6E 67 65 6C 2E 6E 65 74}
		$s2 = {24 61 64 6D 69 6E 5B 27 63 6F 6F 6B 69 65 6C 69 66 65 27 5D 20 3D 20 38 36 34 30 30 3B}
		$s3 = {24 65 72 72 6D 73 67 20 3D 20 27 54 68 65 20 66 69 6C 65 20 79 6F 75 20 77 61 6E 74 20 44 6F 77 6E 6C 6F 61 64 61 62 6C 65 20 77 61 73 20 6E 6F 6E 65 78 69 73 74 65 6E 74 27 3B}

	condition:
		1 of them
}

rule ak74shell_php_php
{
	meta:
		description = "Semi-Auto-generated  - file ak74shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "7f83adcb4c1111653d30c6427a94f66f"

	strings:
		$s1 = {24 72 65 73 20 2E 3D 20 27 3C 74 64 20 61 6C 69 67 6E 3D 5C 22 63 65 6E 74 65 72 5C 22 3E 3C 61 20 68 72 65 66 3D 5C 22 27 2E 24 78 73 68 65 6C 6C 2E 27 3F 61 63 74 3D 63 68 6D 6F 64 26 66 69 6C 65 3D 27 2E 24 5F 53 45 53 53 49 4F 4E 5B}
		$s2 = {41 4B 2D 37 34 20 53 65 63 75 72 69 74 79 20 54 65 61 6D 20 57 65 62 20 53 69 74 65 3A 20 77 77 77 2E 61 6B 37 34 2D 74 65 61 6D 2E 6E 65 74}
		$s3 = {24 78 73 68 65 6C 6C}

	condition:
		2 of them
}

rule Rem_View_php_php
{
	meta:
		description = "Semi-Auto-generated  - file Rem View.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "29420106d9a81553ef0d1ca72b9934d9"

	strings:
		$s0 = {24 70 68 70 3D 5C 22 2F 2A 20 6C 69 6E 65 20 31 20 2A 2F 5C 5C 6E 5C 5C 6E 2F 2F 20 5C 22 2E 6D 6D 28 5C 22 66 6F 72 20 65 78 61 6D 70 6C 65 2C 20 75 6E 63 6F 6D 6D 65 6E 74 20 6E 65 78 74 20 6C 69 6E 65 5C 22 29 2E 5C 22}
		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 73 75 62 6D 69 74 20 76 61 6C 75 65 3D 27 5C 22 2E 6D 6D 28 5C 22 44 65 6C 65 74 65 20 61 6C 6C 20 64 69 72 2F 66 69 6C 65 73 20 72 65 63 75 72 73 69 76 65 5C 22 29 2E 5C 22 20 28 72 6D 20 2D 66 72 29 27}
		$s4 = {57 65 6C 63 6F 6D 65 20 74 6F 20 70 68 70 52 65 6D 6F 74 65 56 69 65 77 20 28 52 65 6D 56 69 65 77 29}

	condition:
		1 of them
}

rule Java_Shell_js
{
	meta:
		description = "Semi-Auto-generated  - file Java Shell.js.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "36403bc776eb12e8b7cc0eb47c8aac83"

	strings:
		$s2 = {50 79 53 79 73 74 65 6D 53 74 61 74 65 2E 69 6E 69 74 69 61 6C 69 7A 65 28 53 79 73 74 65 6D 2E 67 65 74 50 72 6F 70 65 72 74 69 65 73 28 29 2C 20 6E 75 6C 6C 2C 20 61 72 67 76 29 3B}
		$s3 = {70 75 62 6C 69 63 20 63 6C 61 73 73 20 4A 79 74 68 6F 6E 53 68 65 6C 6C 20 65 78 74 65 6E 64 73 20 4A 50 61 6E 65 6C 20 69 6D 70 6C 65 6D 65 6E 74 73 20 52 75 6E 6E 61 62 6C 65 20 7B}
		$s4 = {70 75 62 6C 69 63 20 73 74 61 74 69 63 20 69 6E 74 20 44 45 46 41 55 4C 54 5F 53 43 52 4F 4C 4C 42 41 43 4B 20 3D 20 31 30 30}

	condition:
		2 of them
}

rule STNC_php_php
{
	meta:
		description = "Semi-Auto-generated  - file STNC.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2e56cfd5b5014cbbf1c1e3f082531815"

	strings:
		$s0 = {64 72 6D 69 73 74 2E 72 75}
		$s1 = {68 69 64 64 65 6E 28 5C 22 61 63 74 69 6F 6E 5C 22 2C 5C 22 64 6F 77 6E 6C 6F 61 64 5C 22 29 2E 68 69 64 64 65 6E 5F 70 77 64 28 29 2E 5C 22 3C 63 65 6E 74 65 72 3E 3C 74 61 62 6C 65 3E 3C 74 72 3E 3C 74 64 20 77 69 64 74 68 3D 38 30}
		$s2 = {53 54 4E 43 20 57 65 62 53 68 65 6C 6C}
		$s3 = {68 74 74 70 3A 2F 2F 77 77 77 2E 73 65 63 75 72 69 74 79 2D 74 65 61 6D 73 2E 6E 65 74 2F 69 6E 64 65 78 2E 70 68 70 3F 73 68 6F 77 74 6F 70 69 63 3D}

	condition:
		1 of them
}

rule aZRaiLPhp_v1_0_php
{
	meta:
		description = "Semi-Auto-generated  - file aZRaiLPhp v1.0.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "26b2d3943395682e36da06ed493a3715"

	strings:
		$s0 = {61 7A 72 61 69 6C 70 68 70}
		$s1 = {3C 62 72 3E 3C 63 65 6E 74 65 72 3E 3C 49 4E 50 55 54 20 54 59 50 45 3D 27 53 55 42 4D 49 54 27 20 4E 41 4D 45 3D 27 64 79 27 20 56 41 4C 55 45 3D 27 44 6F 73 79 61 20 59 6F 6C 6C 61 21 27 3E 3C 2F 63 65 6E 74 65 72 3E}
		$s3 = {3C 63 65 6E 74 65 72 3E 3C 49 4E 50 55 54 20 54 59 50 45 3D 27 73 75 62 6D 69 74 27 20 6E 61 6D 65 3D 27 6F 6B 6D 66 27 20 76 61 6C 75 65 3D 27 54 41 4D 41 4D 27 3E 3C 2F 63 65 6E 74 65 72 3E}

	condition:
		2 of them
}

rule Moroccan_Spamers_Ma_EditioN_By_GhOsT_php
{
	meta:
		description = "Semi-Auto-generated  - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d1b7b311a7ffffebf51437d7cd97dc65"

	strings:
		$s0 = {3B 24 73 64 39 38 3D 5C 22 6A 6F 68 6E 2E 62 61 72 6B 65 72 34 34 36 40 67 6D 61 69 6C 2E 63 6F 6D 5C 22}
		$s1 = {70 72 69 6E 74 20 5C 22 53 65 6E 64 69 6E 67 20 6D 61 69 6C 20 74 6F 20 24 74 6F 2E 2E 2E 2E 2E 2E 2E 20 5C 22 3B}
		$s2 = {3C 74 64 20 63 6F 6C 73 70 61 6E 3D 5C 22 32 5C 22 20 77 69 64 74 68 3D 5C 22 37 31 35 5C 22 20 62 61 63 6B 67 72 6F 75 6E 64 3D 5C 22 2F 73 69 6D 70 61 72 74 73 2F 69 6D 61 67 65 73 2F 63 65 6C 6C 70 69 63 31 2E 67 69 66 5C 22 20 68 65 69}

	condition:
		1 of them
}

rule zacosmall_php
{
	meta:
		description = "Semi-Auto-generated  - file zacosmall.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5295ee8dc2f5fd416be442548d68f7a6"

	strings:
		$s0 = {72 61 6E 64 28 31 2C 39 39 39 39 39 29 3B 24 73 6A 39 38}
		$s1 = {24 64 75 6D 70 5F 66 69 6C 65 2E 3D 27 60 27 2E 24 72 6F 77 73 32 5B 30 5D 2E 27 60}
		$s3 = {66 69 6C 65 6E 61 6D 65 3D 5C 5C 5C 22 64 75 6D 70 5F 7B 24 64 62 5F 64 75 6D 70 7D 5F 24 7B 74 61 62 6C 65 5F 64}

	condition:
		2 of them
}

rule CmdAsp_asp
{
	meta:
		description = "Semi-Auto-generated  - file CmdAsp.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "64f24f09ec6efaa904e2492dffc518b9"

	strings:
		$s0 = {43 6D 64 41 73 70 2E 61 73 70}
		$s1 = {53 65 74 20 6F 46 69 6C 65 53 79 73 20 3D 20 53 65 72 76 65 72 2E 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 53 63 72 69 70 74 69 6E 67 2E 46 69 6C 65 53 79 73 74 65 6D 4F 62 6A 65 63 74 5C 22 29}
		$s2 = {2D 2D 20 55 73 65 20 61 20 70 6F 6F 72 20 6D 61 6E 27 73 20 70 69 70 65 20 2E 2E 2E 20 61 20 74 65 6D 70 20 66 69 6C 65 20 2D 2D}
		$s3 = {6D 61 63 65 6F 20 40 20 64 6F 67 6D 69 6C 65 2E 63 6F 6D}

	condition:
		2 of them
}

rule simple_backdoor_php
{
	meta:
		description = "Semi-Auto-generated  - file simple-backdoor.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "f091d1b9274c881f8e41b2f96e6b9936"

	strings:
		$s0 = {24 63 6D 64 20 3D 20 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 3B}
		$s1 = {3C 21 2D 2D 20 53 69 6D 70 6C 65 20 50 48 50 20 62 61 63 6B 64 6F 6F 72 20 62 79 20 44 4B 20 28 68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 29 20 2D 2D 3E}
		$s2 = {55 73 61 67 65 3A 20 68 74 74 70 3A 2F 2F 74 61 72 67 65 74 2E 63 6F 6D 2F 73 69 6D 70 6C 65 2D 62 61 63 6B 64 6F 6F 72 2E 70 68 70 3F 63 6D 64 3D 63 61 74 2B 2F 65 74 63 2F 70 61 73 73 77 64}

	condition:
		2 of them
}

rule mysql_shell_php
{
	meta:
		description = "Semi-Auto-generated  - file mysql_shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d42aec2891214cace99b3eb9f3e21a63"

	strings:
		$s0 = {53 6F 6F 4D 69 6E 20 4B 69 6D}
		$s1 = {73 6D 6B 69 6D 40 70 6F 70 65 79 65 2E 73 6E 75 2E 61 63 2E 6B 72}
		$s2 = {65 63 68 6F 20 5C 22 3C 74 64 3E 3C 61 20 68 72 65 66 3D 27 24 50 48 50 5F 53 45 4C 46 3F 61 63 74 69 6F 6E 3D 64 65 6C 65 74 65 44 61 74 61 26 64 62 6E 61 6D 65 3D 24 64 62 6E 61 6D 65 26 74 61 62 6C 65 6E 61 6D 65 3D 24 74 61 62 6C 65 6E}

	condition:
		1 of them
}

rule Dive_Shell_1_0___Emperor_Hacking_Team_php
{
	meta:
		description = "Semi-Auto-generated  - file Dive Shell 1.0 - Emperor Hacking Team.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1b5102bdc41a7bc439eea8f0010310a5"

	strings:
		$s0 = {45 6D 70 65 72 6F 72 20 48 61 63 6B 69 6E 67 20 54 45 41 4D}
		$s1 = {53 69 6D 73 68 65 6C 6C}
		$s2 = {65 72 65 67 28 27 5E 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2A 63 64 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D}
		$s3 = {3C 66 6F 72 6D 20 6E 61 6D 65 3D 5C 22 73 68 65 6C 6C 5C 22 20 61 63 74 69 6F 6E 3D 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 53 45 4C 46 27 5D 20 3F 3E 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54}

	condition:
		2 of them
}

rule Asmodeus_v0_1_pl
{
	meta:
		description = "Semi-Auto-generated  - file Asmodeus v0.1.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0978b672db0657103c79505df69cb4bb"

	strings:
		$s0 = {5B 75 72 6C 3D 68 74 74 70 3A 2F 2F 77 77 77 2E 67 6F 76 65 72 6E 6D 65 6E 74 73 65 63 75 72 69 74 79 2E 6F 72 67}
		$s1 = {70 65 72 6C 20 61 73 6D 6F 64 65 75 73 2E 70 6C 20 63 6C 69 65 6E 74 20 36 36 36 36 20 31 32 37 2E 30 2E 30 2E 31}
		$s2 = {70 72 69 6E 74 20 5C 22 41 73 6D 6F 64 65 75 73 20 50 65 72 6C 20 52 65 6D 6F 74 65 20 53 68 65 6C 6C}
		$s4 = {24 69 6E 74 65 72 6E 65 74 5F 61 64 64 72 20 3D 20 69 6E 65 74 5F 61 74 6F 6E 28 5C 22 24 68 6F 73 74 5C 22 29 20 6F 72 20 64 69 65 20 5C 22 41 4C 4F 41 3A 24 21 5C 5C 6E 5C 22 3B}

	condition:
		2 of them
}

rule backup_php_often_with_c99shell
{
	meta:
		description = "Semi-Auto-generated  - file backup.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "aeee3bae226ad57baf4be8745c3f6094"

	strings:
		$s0 = {23 70 68 70 4D 79 41 64 6D 69 6E 20 4D 79 53 51 4C 2D 44 75 6D 70}
		$s2 = {3B 64 62 5F 63 6F 6E 6E 65 63 74 28 29 3B 68 65 61 64 65 72 28 27 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 73 74 72}
		$s4 = {24 64 61 74 61 20 2E 3D 20 5C 22 23 44 61 74 61 62 61 73 65 3A 20 24 64 61 74 61 62 61 73 65}

	condition:
		all of them
}

rule Reader_asp
{
	meta:
		description = "Semi-Auto-generated  - file Reader.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ad1a362e0a24c4475335e3e891a01731"

	strings:
		$s1 = {4D 65 68 64 69 20 26 20 48 6F 6C 79 44 65 6D 6F 6E}
		$s2 = {77 77 77 2E 69 6E 66 69 6C 61 6B 2E}
		$s3 = {27 2A 54 40 2A 72 40 23 40 26 6D 6D 73 5E 50 64 62 59 62 56 75 42 63 41 41 41 3D 3D 5E 23 7E 40 25 3E 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 70 6F 73 74 20 6E 61 6D 65 3D 69 6E 66 3E 3C 74 61 62 6C 65 20 77 69 64 74 68 3D 5C 22 37 35 25}

	condition:
		2 of them
}

rule phpshell17_php
{
	meta:
		description = "Semi-Auto-generated  - file phpshell17.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9a928d741d12ea08a624ee9ed5a8c39d"

	strings:
		$s0 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 73 75 62 6D 69 74 5F 62 74 6E 5C 22 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 45 78 65 63 75 74 65 20 43 6F 6D 6D 61 6E 64 5C 22 3E 3C 2F 70 3E}
		$s1 = {3C 74 69 74 6C 65 3E 5B 41 44 44 49 54 49 4E 41 4C 20 54 49 54 54 4C 45 5D 2D 70 68 70 53 68 65 6C 6C 20 62 79 3A 5B 59 4F 55 52 4E 41 4D 45 5D 3C 3F 70 68 70 20 65 63 68 6F 20 50 48 50 53 48 45 4C 4C 5F 56 45 52 53 49 4F 4E 20 3F 3E 3C 2F}
		$s2 = {68 72 65 66 3D 5C 22 6D 61 69 6C 74 6F 3A 20 5B 59 4F 55 20 43 41 4E 20 45 4E 54 45 52 20 59 4F 55 52 20 4D 41 49 4C 20 48 45 52 45 5D 2D 20 5B 41 44 44 49 54 49 4F 4E 41 4C 20 54 45 58 54 5D 3C 2F 61 3E 3C 2F 69 3E}

	condition:
		1 of them
}

rule myshell_php_php
{
	meta:
		description = "Semi-Auto-generated  - file myshell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "62783d1db52d05b1b6ae2403a7044490"

	strings:
		$s0 = {40 63 68 64 69 72 28 24 77 6F 72 6B 5F 64 69 72 29 20 6F 72 20 28 24 73 68 65 6C 6C 4F 75 74 70 75 74 20 3D 20 5C 22 4D 79 53 68 65 6C 6C 3A 20 63 61 6E 27 74 20 63 68 61 6E 67 65 20 64 69 72 65 63 74 6F 72 79 2E}
		$s1 = {65 63 68 6F 20 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 24 6C 69 6E 6B 43 6F 6C 6F 72 3E 3C 62 3E 4D 79 53 68 65 6C 6C 20 66 69 6C 65 20 65 64 69 74 6F 72 3C 2F 66 6F 6E 74 3E 20 46 69 6C 65 3A 3C 66 6F 6E 74 20 63 6F 6C 6F 72}
		$s2 = {20 24 66 69 6C 65 45 64 69 74 49 6E 66 6F 20 3D 20 5C 22 26 6E 62 73 70 3B 26 6E 62 73 70 3B 3A 3A 3A 3A 3A 3A 3A 26 6E 62 73 70 3B 26 6E 62 73 70 3B 4F 77 6E 65 72 3A 20 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 24}

	condition:
		2 of them
}

rule SimShell_1_0___Simorgh_Security_MGZ_php
{
	meta:
		description = "Semi-Auto-generated  - file SimShell 1.0 - Simorgh Security MGZ.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "37cb1db26b1b0161a4bf678a6b4565bd"

	strings:
		$s0 = {53 69 6D 6F 72 67 68 20 53 65 63 75 72 69 74 79 20 4D 61 67 61 7A 69 6E 65 20}
		$s1 = {53 69 6D 73 68 65 6C 6C 2E 63 73 73}
		$s2 = {7D 20 65 6C 73 65 69 66 20 28 65 72 65 67 28 27 5E 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2A 63 64 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2B 28 5B 5E 3B 5D 2B 29 24 27 2C 20 24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 2C 20}
		$s3 = {77 77 77 2E 73 69 6D 6F 72 67 68 2D 65 76 2E 63 6F 6D}

	condition:
		2 of them
}

rule jspshall_jsp
{
	meta:
		description = "Semi-Auto-generated  - file jspshall.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "efe0f6edaa512c4e1fdca4eeda77b7ee"

	strings:
		$s0 = {6B 6A 30 32 31 33 32 30}
		$s1 = {63 61 73 65 20 27 54 27 3A 73 79 73 74 65 6D 54 6F 6F 6C 73 28 6F 75 74 29 3B 62 72 65 61 6B 3B}
		$s2 = {6F 75 74 2E 70 72 69 6E 74 6C 6E 28 5C 22 3C 74 72 3E 3C 74 64 3E 5C 22 2B 69 63 6F 28 35 30 29 2B 66 5B 69 5D 2E 67 65 74 4E 61 6D 65 28 29 2B 5C 22 3C 2F 74 64 3E 3C 74 64 3E 20 66 69 6C 65}

	condition:
		2 of them
}

rule webshell_php
{
	meta:
		description = "Semi-Auto-generated  - file webshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "e425241b928e992bde43dd65180a4894"

	strings:
		$s2 = {3C 64 69 65 28 5C 22 43 6F 75 6C 64 6E 27 74 20 52 65 61 64 20 64 69 72 65 63 74 6F 72 79 2C 20 42 6C 6F 63 6B 65 64 21 21 21 5C 22 29 3B}
		$s3 = {50 48 50 20 57 65 62 20 53 68 65 6C 6C}

	condition:
		all of them
}

rule rootshell_php
{
	meta:
		description = "Semi-Auto-generated  - file rootshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "265f3319075536030e59ba2f9ef3eac6"

	strings:
		$s0 = {73 68 65 6C 6C 73 2E 64 6C 2E 61 6D}
		$s1 = {54 68 69 73 20 73 65 72 76 65 72 20 68 61 73 20 62 65 65 6E 20 69 6E 66 65 63 74 65 64 20 62 79 20 24 6F 77 6E 65 72}
		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 49 6E 63 6C 75 64 65 21 5C 22 20 6E 61 6D 65 3D 5C 22 69 6E 63 5C 22 3E 3C 2F 70 3E}
		$s4 = {43 6F 75 6C 64 20 6E 6F 74 20 77 72 69 74 65 20 74 6F 20 66 69 6C 65 21 20 28 4D 61 79 62 65 20 79 6F 75 20 64 69 64 6E 27 74 20 65 6E 74 65 72 20 61 6E 79 20 74 65 78 74 3F 29}

	condition:
		2 of them
}

rule connectback2_pl
{
	meta:
		description = "Semi-Auto-generated  - file connectback2.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "473b7d226ea6ebaacc24504bd740822e"

	strings:
		$s0 = {23 57 65 20 41 72 65 3A 20 4D 61 73 74 65 72 4B 69 64 2C 20 41 6C 65 58 75 74 7A 2C 20 46 61 74 4D 61 6E 20 26 20 4D 69 4B 75 54 75 4C 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20}
		$s1 = {65 63 68 6F 20 2D 2D 3D 3D 55 73 65 72 69 6E 66 6F 3D 3D 2D 2D 20 3B 20 69 64 3B 65 63 68 6F 3B 65 63 68 6F 20 2D 2D 3D 3D 44 69 72 65 63 74 6F 72 79 3D 3D 2D 2D 20 3B 20 70 77 64 3B 65 63 68 6F 3B 20 65 63 68 6F 20 2D 2D 3D 3D 53 68 65 6C}
		$s2 = {43 6F 6E 6E 65 63 74 42 61 63 6B 20 42 61 63 6B 64 6F 6F 72}

	condition:
		1 of them
}

rule DefaceKeeper_0_2_php
{
	meta:
		description = "Semi-Auto-generated  - file DefaceKeeper_0.2.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "713c54c3da3031bc614a8a55dccd7e7f"

	strings:
		$s0 = {74 61 72 67 65 74 20 66 69 31 65 3A 3C 62 72 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 74 61 72 67 65 74 5C 22 20 76 61 6C 75 65 3D 5C 22 69 6E 64 65 78 2E 70 68 70 5C 22 3E 3C 2F 62 72 3E}
		$s1 = {65 76 61 6C 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 5C 22 5A 58 5A 68 62 43 68 69 59 58 4E 6C 4E 6A 52 66 5A 47 56 6A 62 32 52 6C 4B 43 4A 68 56 32 52 31 59 6A 4E 4B 62 46 67 7A 56 6E 70 61 57 45 70 6D 57 56 64 4B 64 6D 4E 75 55 57 39}
		$s2 = {3C 69 6D 67 20 73 72 63 3D 5C 22 68 74 74 70 3A 2F 2F 73 34 33 2E 72 61 64 69 6B 61 6C 2E 72 75 2F 69 31 30 31 2F 31 30 30 34 2F 64 38 2F 63 65 64 31 66 36 62 32 66 35 61 39 2E 70 6E 67 5C 22 20 61 6C 69 67 6E 3D 5C 22 63 65 6E 74 65 72}

	condition:
		1 of them
}

rule shells_PHP_wso
{
	meta:
		description = "Semi-Auto-generated  - file wso.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "33e2891c13b78328da9062fbfcf898b6"

	strings:
		$s0 = {24 62 61 63 6B 5F 63 6F 6E 6E 65 63 74 5F 70 3D 5C 22 49 79 45 76 64 58 4E 79 4C 32 4A 70 62 69 39 77 5A 58 4A 73 44 51 70 31 63 32 55 67 55 32 39 6A 61 32 56 30 4F 77 30 4B 4A 47 6C 68 5A 47 52 79 50 57 6C 75 5A 58 52 66 59 58 52 76 62 69}
		$s3 = {65 63 68 6F 20 27 3C 68 31 3E 45 78 65 63 75 74 69 6F 6E 20 50 48 50 2D 63 6F 64 65 3C 2F 68 31 3E 3C 64 69 76 20 63 6C 61 73 73 3D 63 6F 6E 74 65 6E 74 3E 3C 66 6F 72 6D 20 6E 61 6D 65 3D 70 66 20 6D 65 74 68 6F 64 3D 70 6F 73}

	condition:
		1 of them
}

rule backdoor1_php
{
	meta:
		description = "Semi-Auto-generated  - file backdoor1.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "e1adda1f866367f52de001257b4d6c98"

	strings:
		$s1 = {65 63 68 6F 20 5C 22 5B 44 49 52 5D 20 3C 41 20 48 52 45 46 3D 5C 5C 5C 22 5C 22 2E 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 53 45 4C 46 27 5D 2E 5C 22 3F 72 65 70 3D 5C 22 2E 72 65 61 6C 70 61 74 68 28 24 72 65 70 2E 5C 22 2E 2E}
		$s2 = {63 6C 61 73 73 20 62 61 63 6B 64 6F 6F 72 20 7B}
		$s4 = {65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 5C 22 2E 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 53 45 4C 46 27 5D 2E 5C 22 3F 63 6F 70 79 3D 31 5C 5C 5C 22 3E 43 6F 70 69 65 72 20 75 6E 20 66 69 63 68 69 65 72 3C 2F 61 3E 20 3C}

	condition:
		1 of them
}

rule elmaliseker_asp
{
	meta:
		description = "Semi-Auto-generated  - file elmaliseker.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"

	strings:
		$s0 = {69 66 20 49 6E 74 28 28 31 2D 30 2B 31 29 2A 52 6E 64 2B 30 29 3D 30 20 74 68 65 6E 20 6D 61 6B 65 45 6D 61 69 6C 3D 6D 61 6B 65 54 65 78 74 28 38 29 20 26 20 5C 22 40 5C 22 20 26 20 6D 61 6B 65 54 65 78 74 28 38 29 20 26 20 5C 22 2E 5C 22}
		$s1 = {3C 66 6F 72 6D 20 6E 61 6D 65 3D 66 72 6D 43 4D 44 20 6D 65 74 68 6F 64 3D 70 6F 73 74 20 61 63 74 69 6F 6E 3D 5C 22 3C 25 3D 67 55 52 4C 25 3E 5C 22 3E}
		$s2 = {64 69 6D 20 7A 6F 6D 62 69 65 5F 61 72 72 61 79 2C 73 70 65 63 69 61 6C 5F 61 72 72 61 79}
		$s3 = {68 74 74 70 3A 2F 2F 76 6E 68 61 63 6B 65 72 2E 6F 72 67}

	condition:
		1 of them
}

rule indexer_asp
{
	meta:
		description = "Semi-Auto-generated  - file indexer.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9ea82afb8c7070817d4cdf686abe0300"

	strings:
		$s0 = {3C 74 64 3E 4E 65 72 65 79 65 20 3A 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 6E 65 72 65 79 65 5C 22 20 73 69 7A 65 3D 32 35 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70}
		$s2 = {44 37 6E 44 37 6C 2E 6B 6D 34 73 6E 6B 60 4A 7A 4B 6E 64 7B 6E 5F 65 6A 71 3B 62 64 7B 4B 62 50 75 72 23 6B 51 38 41 41 41 3D 3D 5E 23 7E 40 25 3E 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74}

	condition:
		1 of them
}

rule DxShell_php_php
{
	meta:
		description = "Semi-Auto-generated  - file DxShell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "33a2b31810178f4c2e71fbdeb4899244"

	strings:
		$s0 = {70 72 69 6E 74 20 5C 22 5C 5C 6E 5C 22 2E 27 54 69 70 3A 20 74 6F 20 76 69 65 77 20 74 68 65 20 66 69 6C 65 20 5C 22 61 73 20 69 73 5C 22 20 2D 20 6F 70 65 6E 20 74 68 65 20 70 61 67 65 20 69 6E 20 3C 61 20 68 72 65 66 3D 5C 22 27 2E 44 78}
		$s2 = {70 72 69 6E 74 20 5C 22 5C 5C 6E 5C 22 2E 27 3C 74 72 3E 3C 74 64 20 77 69 64 74 68 3D 31 30 30 70 74 20 63 6C 61 73 73 3D 6C 69 6E 65 6C 69 73 74 69 6E 67 3E 3C 6E 6F 62 72 3E 50 4F 53 54 20 28 70 68 70 20 65 76 61 6C 29 3C 2F 74 64 3E 3C}

	condition:
		1 of them
}

rule s72_Shell_v1_1_Coding_html
{
	meta:
		description = "Semi-Auto-generated  - file s72 Shell v1.1 Coding.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c2e8346a5515c81797af36e7e4a3828e"

	strings:
		$s0 = {44 69 7A 69 6E 3C 2F 66 6F 6E 74 3E 3C 2F 62 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 22 56 65 72 64 61 6E 61 5C 22 20 73 74 79 6C 65 3D 5C 22 66 6F 6E 74 2D 73 69 7A 65 3A 20 38 70 74 5C 22 3E 3C}
		$s1 = {73 37 32 20 53 68 65 6C 6C 20 76 31 2E 30 20 43 6F 64 69 6E 66 20 62 79 20 43 72 40 7A 79 5F 4B 69 6E 67}
		$s3 = {65 63 68 6F 20 5C 22 3C 70 20 61 6C 69 67 6E 3D 63 65 6E 74 65 72 3E 44 6F 73 79 61 20 5A 61 74 65 6E 20 42 75 6C 75 6E 75 79 6F 72 3C 2F 70 3E 5C 22}

	condition:
		1 of them
}

// duplicated
/* rule hidshell_php_php
{
	meta:
		description = "Semi-Auto-generated  - file hidshell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c2f3327d60884561970c63ffa09439a4"

	strings:
		$s0 = {3C 3F 24 64 3D 27 47 37 6D 48 57 51 39 76 76 58 69 4C 2F 51 58 32 6F 5A 32 56 54 44 70 6F 36 67 33 46 59 41 61 36 58 2B 38 44 4D 49 7A 63 44 30 65 48 5A 61 42 5A 48 37 6A 46 70 5A 7A 55 7A 37 58 4E 65 6E 78 53 59 76 42 50 32 57 79 33 36 55}

	condition:
		all of them
}*/

rule kacak_asp
{
	meta:
		description = "Semi-Auto-generated  - file kacak.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "907d95d46785db21331a0324972dda8c"

	strings:
		$s0 = {4B 61 63 61 6B 20 46 53 4F 20 31 2E 30}
		$s1 = {69 66 20 72 65 71 75 65 73 74 2E 71 75 65 72 79 73 74 72 69 6E 67 28 5C 22 54 47 48 5C 22 29 20 3D 20 5C 22 31 5C 22 20 74 68 65 6E}
		$s3 = {3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 38 35 38 35 38 35 5C 22 3E 42 75 71 58 3C 2F 66 6F 6E 74 3E 3C 2F 61 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 5C 22 56 65 72 64 61 6E 61 5C 22 20 73 74 79 6C 65 3D}
		$s4 = {6D 61 69 6C 74 6F 3A 42 75 71 58 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D}

	condition:
		1 of them
}

rule PHP_Backdoor_Connect_pl_php
{
	meta:
		description = "Semi-Auto-generated  - file PHP Backdoor Connect.pl.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "57fcd9560dac244aeaf95fd606621900"

	strings:
		$s0 = {4C 6F 72 44 20 6F 66 20 49 52 41 4E 20 48 41 43 4B 45 52 53 20 53 41 42 4F 54 41 47 45}
		$s1 = {4C 6F 72 44 2D 43 30 64 33 72 2D 4E 54}
		$s2 = {65 63 68 6F 20 2D 2D 3D 3D 55 73 65 72 69 6E 66 6F 3D 3D 2D 2D 20 3B}

	condition:
		1 of them
}

rule Antichat_Socks5_Server_php_php
{
	meta:
		description = "Semi-Auto-generated  - file Antichat Socks5 Server.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "cbe9eafbc4d86842a61a54d98e5b61f1"

	strings:
		$s0 = {24 70 6F 72 74 20 3D 20 62 61 73 65 5F 63 6F 6E 76 65 72 74 28 62 69 6E 32 68 65 78 28 73 75 62 73 74 72 28 24 72 65 71 6D 65 73 73 61 67 65 5B 24 69 64 5D 2C 20 33 2B 24 72 65 71 6C 65 6E 2B 31 2C 20 32 29 29 2C 20 31 36 2C 20 31 30 29 3B}
		$s3 = {23 20 20 20 5B 2B 5D 20 44 6F 6D 61 69 6E 20 6E 61 6D 65 20 61 64 64 72 65 73 73 20 74 79 70 65}
		$s4 = {77 77 77 2E 61 6E 74 69 63 68 61 74 2E 72 75}

	condition:
		1 of them
}

rule Antichat_Shell_v1_3_php
{
	meta:
		description = "Semi-Auto-generated  - file Antichat Shell v1.3.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "40d0abceba125868be7f3f990f031521"

	strings:
		$s0 = {41 6E 74 69 63 68 61 74}
		$s1 = {43 61 6E 27 74 20 6F 70 65 6E 20 66 69 6C 65 2C 20 70 65 72 6D 69 73 73 69 6F 6E 20 64 65 6E 69 64 65}
		$s2 = {24 72 61 34 34}

	condition:
		2 of them
}

rule Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_php
{
	meta:
		description = "Semi-Auto-generated  - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "49ad9117c96419c35987aaa7e2230f63"

	strings:
		$s0 = {57 65 6C 63 6F 6D 65 2E 2E 20 42 79 20 54 68 69 73 20 73 63 72 69 70 74 20 79 6F 75 20 63 61 6E 20 6A 75 6D 70 20 69 6E 20 74 68 65 20 28 53 61 66 65 20 4D 6F 64 65 3D 4F 4E 29 20 2E 2E 20 45 6E 6A 6F 79}
		$s1 = {4D 6F 64 65 20 53 68 65 6C 6C 20 76 31 2E 30 3C 2F 66 6F 6E 74 3E 3C 2F 73 70 61 6E 3E}
		$s2 = {68 61 73 20 62 65 65 6E 20 61 6C 72 65 61 64 79 20 6C 6F 61 64 65 64 2E 20 50 48 50 20 45 6D 70 65 72 6F 72 20 3C 78 62 35 40 68 6F 74 6D 61 69 6C 2E}

	condition:
		1 of them
}

rule mysql_php_php
{
	meta:
		description = "Semi-Auto-generated  - file mysql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "12bbdf6ef403720442a47a3cc730d034"

	strings:
		$s0 = {61 63 74 69 6F 6E 3D 6D 79 73 71 6C 72 65 61 64 26 6D 61 73 73 3D 6C 6F 61 64 6D 61 73 73 5C 22 3E 6C 6F 61 64 20 61 6C 6C 20 64 65 66 61 75 6C 74 73}
		$s2 = {69 66 20 28 40 70 61 73 73 74 68 72 75 28 24 63 6D 64 29 29 20 7B 20 65 63 68 6F 20 5C 22 20 2D 2D 3E 5C 22 3B 20 24 74 68 69 73 2D 3E 6F 75 74 70 75 74 5F 73 74 61 74 65 28 31 2C 20 5C 22 70 61 73 73 74 68 72 75}
		$s3 = {24 72 61 34 34 20 20 3D 20 72 61 6E 64 28 31 2C 39 39 39 39 39 29 3B 24 73 6A 39 38 20 3D 20 5C 22 73 68 2D 24 72 61 34 34 5C 22 3B 24 6D 6C 20 3D 20 5C 22 24 73 64 39 38 5C 22 3B 24 61 35 20 3D 20}

	condition:
		1 of them
}

rule Worse_Linux_Shell_php
{
	meta:
		description = "Semi-Auto-generated  - file Worse Linux Shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8338c8d9eab10bd38a7116eb534b5fa2"

	strings:
		$s1 = {70 72 69 6E 74 20 5C 22 3C 74 72 3E 3C 74 64 3E 3C 62 3E 53 65 72 76 65 72 20 69 73 3A 3C 2F 62 3E 3C 2F 74 64 3E 3C 74 64 3E 5C 22 2E 24 5F 53 45 52 56 45 52 5B 27 53 45 52 56 45 52 5F 53 49 47 4E 41 54 55 52 45 27 5D 2E 5C 22 3C 2F 74 64}
		$s2 = {70 72 69 6E 74 20 5C 22 3C 74 72 3E 3C 74 64 3E 3C 62 3E 45 78 65 63 75 74 65 20 63 6F 6D 6D 61 6E 64 3A 3C 2F 62 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74 20 73 69 7A 65 3D 31 30 30 20 6E 61 6D 65 3D 5C 5C 5C 22 5F 63 6D 64}

	condition:
		1 of them
}

rule cyberlords_sql_php_php
{
	meta:
		description = "Semi-Auto-generated  - file cyberlords_sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "03b06b4183cb9947ccda2c3d636406d4"

	strings:
		$s0 = {43 6F 64 65 64 20 62 79 20 6E 30 20 5B 6E 5A 65 72 30 5D}
		$s1 = {20 77 77 77 2E 63 79 62 65 72 6C 6F 72 64 73 2E 6E 65 74}
		$s2 = {55 32 39 6D 64 48 64 68 63 6D 55 41 51 57 52 76 59 6D 55 67 53 57 31 68 5A 32 56 53 5A 57 46 6B 65 58 48 4A 5A 54 77 41 41 41 41 4D 55 45 78 55 52 66 2F 2F 2F 77 41 41 41 4A 6D 5A 7A 41 41 41 41 43 4A 6F 55 52 6B 41 41 41 41 45}
		$s3 = {72 65 74 75 72 6E 20 5C 22 3C 42 52 3E 44 75 6D 70 20 65 72 72 6F 72 21 20 43 61 6E 27 74 20 77 72 69 74 65 20 74 6F 20 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 66 69 6C 65 29 3B}

	condition:
		1 of them
}

rule cmd_asp_5_1_asp
{
	meta:
		description = "Semi-Auto-generated  - file cmd-asp-5.1.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8baa99666bf3734cbdfdd10088e0cd9f"

	strings:
		$s0 = {43 61 6C 6C 20 6F 53 2E 52 75 6E 28 5C 22 77 69 6E 2E 63 6F 6D 20 63 6D 64 2E 65 78 65 20 2F 63 20 64 65 6C 20 5C 22 26 20 73 7A 54 46 2C 30 2C 54 72 75 65 29}
		$s3 = {43 61 6C 6C 20 6F 53 2E 52 75 6E 28 5C 22 77 69 6E 2E 63 6F 6D 20 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 5C 22 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 46 20 26}

	condition:
		1 of them
}

rule pws_php_php
{
	meta:
		description = "Semi-Auto-generated  - file pws.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ecdc6c20f62f99fa265ec9257b7bf2ce"

	strings:
		$s0 = {3C 64 69 76 20 61 6C 69 67 6E 3D 5C 22 6C 65 66 74 5C 22 3E 3C 66 6F 6E 74 20 73 69 7A 65 3D 5C 22 31 5C 22 3E 49 6E 70 75 74 20 63 6F 6D 6D 61 6E 64 20 3A 3C 2F 66 6F 6E 74 3E 3C 2F 64 69 76 3E}
		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 63 6D 64 5C 22 20 73 69 7A 65 3D 5C 22 33 30 5C 22 20 63 6C 61 73 73 3D 5C 22 69 6E 70 75 74 5C 22 3E 3C 62 72 3E}
		$s4 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 64 69 72 5C 22 20 73 69 7A 65 3D 5C 22 33 30 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 20 70 61 73 73 74 68 72 75 28 5C 22 70 77 64 5C 22 29 3B 20 3F 3E}

	condition:
		2 of them
}

rule PHP_Shell_php_php
{
	meta:
		description = "Semi-Auto-generated  - file PHP Shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"

	strings:
		$s0 = {65 63 68 6F 20 5C 22 3C 2F 66 6F 72 6D 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 24 53 46 69 6C 65 4E 61 6D 65 3F 24 75 72 6C 41 64 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 70 6F 73 74 5C 5C 5C 22 3E 3C 69 6E 70 75 74}
		$s1 = {65 63 68 6F 20 5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 24 53 46 69 6C 65 4E 61 6D 65 3F 24 75 72 6C 41 64 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50 4F 53 54 5C 5C 5C 22 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D}

	condition:
		all of them
}

rule Ayyildiz_Tim___AYT__Shell_v_2_1_Biz_html
{
	meta:
		description = "Semi-Auto-generated  - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8a8c8bb153bd1ee097559041f2e5cf0a"

	strings:
		$s0 = {41 79 79 69 6C 64 69 7A}
		$s1 = {54 6F 75 43 68 20 42 79 20 69 4A 4F 6F}
		$s2 = {46 69 72 73 74 20 77 65 20 63 68 65 63 6B 20 69 66 20 74 68 65 72 65 20 68 61 73 20 62 65 65 6E 20 61 73 6B 65 64 20 66 6F 72 20 61 20 77 6F 72 6B 69 6E 67 20 64 69 72 65 63 74 6F 72 79}
		$s3 = {68 74 74 70 3A 2F 2F 61 79 79 69 6C 64 69 7A 2E 6F 72 67 2F 69 6D 61 67 65 73 2F 77 68 6F 73 6F 6E 6C 69 6E 65 32 2E 67 69 66}

	condition:
		2 of them
}

rule EFSO_2_asp
{
	meta:
		description = "Semi-Auto-generated  - file EFSO_2.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b5fde9682fd63415ae211d53c6bfaa4d"

	strings:
		$s0 = {45 6A 64 65 72 20 77 61 73 20 48 45 52 45}
		$s1 = {2A 7E 50 55 2A 26 42 50 5B 5F 29 66 21 38 63 32 46 2A 40 23 40 26 7E 2C 50 7E 50 2C 7E 50 26 71 7E 38 42 50 6D 53 7E 39 7E 7E 6C 42 7E 58 60 56 2C 5F 2C 46 26 2A 7E 2C 6A 63 57 7E 7E 5B 5F 63 33 54 52 46 46 7A 71 40 23 40 26 50 50 2C 7E 7E}

	condition:
		2 of them
}

rule lamashell_php
{
	meta:
		description = "Semi-Auto-generated  - file lamashell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "de9abc2e38420cad729648e93dfc6687"

	strings:
		$s0 = {6C 61 6D 61 27 73 27 68 65 6C 6C}
		$s1 = {69 66 28 24 5F 50 4F 53 54 5B 27 6B 69 6E 67 27 5D 20 3D 3D 20 5C 22 5C 22 29 20 7B}
		$s2 = {69 66 20 28 6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 5F 46 49 4C 45 53 5B 27 66 69 6C 61 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 20 24 63 75 72 64 69 72 2E 5C 22 2F 5C 22 2E 24 5F 46 49 4C 45 53 5B 27 66}

	condition:
		1 of them
}

rule Ajax_PHP_Command_Shell_php
{
	meta:
		description = "Semi-Auto-generated  - file Ajax_PHP Command Shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "93d1a2e13a3368a2472043bd6331afe9"

	strings:
		$s1 = {6E 65 77 68 74 6D 6C 20 3D 20 27 3C 62 3E 46 69 6C 65 20 62 72 6F 77 73 65 72 20 69 73 20 75 6E 64 65 72 20 63 6F 6E 73 74 72 75 63 74 69 6F 6E 21 20 55 73 65 20 61 74 20 79 6F 75 72 20 6F 77 6E 20 72 69 73 6B 21 3C 2F 62 3E 20 3C 62 72 3E}
		$s2 = {45 6D 70 74 79 20 43 6F 6D 6D 61 6E 64 2E 2E 74 79 70 65 20 5C 5C 5C 22 73 68 65 6C 6C 68 65 6C 70 5C 5C 5C 22 20 66 6F 72 20 73 6F 6D 65 20 65 68 68 2E 2E 2E 68 65 6C 70}
		$s3 = {6E 65 77 68 74 6D 6C 20 3D 20 27 3C 66 6F 6E 74 20 73 69 7A 65 3D 30 3E 3C 62 3E 54 68 69 73 20 77 69 6C 6C 20 72 65 6C 6F 61 64 20 74 68 65 20 70 61 67 65 2E 2E 2E 20 3A 28 3C 2F 62 3E 3C 62 72 3E 3C 62 72 3E 3C 66 6F 72 6D 20 65 6E 63 74}

	condition:
		1 of them
}

rule JspWebshell_1_2_jsp
{
	meta:
		description = "Semi-Auto-generated  - file JspWebshell 1.2.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "70a0ee2624e5bbe5525ccadc467519f6"

	strings:
		$s0 = {4A 73 70 57 65 62 73 68 65 6C 6C}
		$s1 = {43 72 65 61 74 65 41 6E 64 44 65 6C 65 74 65 46 6F 6C 64 65 72 20 69 73 20 65 72 72 6F 72 3A}
		$s2 = {3C 74 64 20 77 69 64 74 68 3D 5C 22 37 30 25 5C 22 20 68 65 69 67 68 74 3D 5C 22 32 32 5C 22 3E 26 6E 62 73 70 3B 3C 25 3D 65 6E 76 2E 71 75 65 72 79 48 61 73 68 74 61 62 6C 65 28 5C 22 6A 61 76 61 2E 63}
		$s3 = {53 74 72 69 6E 67 20 5F 70 61 73 73 77 6F 72 64 20 3D 5C 22 31 31 31 5C 22 3B}

	condition:
		2 of them
}

rule Sincap_php_php
{
	meta:
		description = "Semi-Auto-generated  - file Sincap.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b68b90ff6012a103e57d141ed38a7ee9"

	strings:
		$s0 = {24 62 61 67 6C 61 6E 3D 66 6F 70 65 6E 28 5C 22 2F 74 6D 70 2F 24 65 6B 69 6E 63 69 5C 22 2C 27 72 27 29 3B}
		$s2 = {24 74 61 6D 70 6F 6E 34 3D 24 74 61 6D 70 6F 6E 33 2D 31}
		$s3 = {40 61 76 65 6E 74 67 72 75 70 2E 6E 65 74}

	condition:
		2 of them
}

rule Test_php_php
{
	meta:
		description = "Semi-Auto-generated  - file Test.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "77e331abd03b6915c6c6c7fe999fcb50"

	strings:
		$s0 = {24 79 61 7A 69 20 3D 20 5C 22 74 65 73 74 5C 22 20 2E 20 5C 22 5C 5C 72 5C 5C 6E 5C 22 3B}
		$s2 = {66 77 72 69 74 65 20 28 24 66 70 2C 20 5C 22 24 79 61 7A 69 5C 22 29 3B}
		$s3 = {24 65 6E 74 72 79 5F 6C 69 6E 65 3D 5C 22 48 41 43 4B 65 64 20 62 79 20 45 6E 74 72 69 4B 61 5C 22 3B}

	condition:
		1 of them
}

rule Phyton_Shell_py
{
	meta:
		description = "Semi-Auto-generated  - file Phyton Shell.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "92b3c897090867c65cc169ab037a0f55"

	strings:
		$s1 = {73 68 5F 6F 75 74 3D 6F 73 2E 70 6F 70 65 6E 28 53 48 45 4C 4C 2B 5C 22 20 5C 22 2B 63 6D 64 29 2E 72 65 61 64 6C 69 6E 65 73 28 29}
		$s2 = {23 20 20 20 64 30 30 72 2E 70 79 20 30 2E 33 61 20 28 72 65 76 65 72 73 65 7C 62 69 6E 64 29 2D 73 68 65 6C 6C 20 69 6E 20 70 79 74 68 6F 6E 20 62 79 20 66 51}
		$s3 = {70 72 69 6E 74 20 5C 22 65 72 72 6F 72 3B 20 68 65 6C 70 3A 20 68 65 61 64 20 2D 6E 20 31 36 20 64 30 30 72 2E 70 79 5C 22}
		$s4 = {70 72 69 6E 74 20 5C 22 50 57 3A 5C 22 2C 50 57 2C 5C 22 50 4F 52 54 3A 5C 22 2C 50 4F 52 54 2C 5C 22 48 4F 53 54 3A 5C 22 2C 48 4F 53 54}

	condition:
		1 of them
}

rule mysql_tool_php_php
{
	meta:
		description = "Semi-Auto-generated  - file mysql_tool.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5fbe4d8edeb2769eda5f4add9bab901e"

	strings:
		$s0 = {24 65 72 72 6F 72 5F 74 65 78 74 20 3D 20 27 3C 73 74 72 6F 6E 67 3E 46 61 69 6C 65 64 20 73 65 6C 65 63 74 69 6E 67 20 64 61 74 61 62 61 73 65 20 5C 22 27 2E 24 74 68 69 73 2D 3E 64 62 5B 27}
		$s1 = {24 72 61 34 34 20 20 3D 20 72 61 6E 64 28 31 2C 39 39 39 39 39 29 3B 24 73 6A 39 38 20 3D 20 5C 22 73 68 2D 24 72 61 34 34 5C 22 3B 24 6D 6C 20 3D 20 5C 22 24 73 64 39 38 5C 22 3B 24 61 35 20 3D 20 24 5F 53 45 52 56}
		$s4 = {3C 64 69 76 20 61 6C 69 67 6E 3D 5C 22 63 65 6E 74 65 72 5C 22 3E 54 68 65 20 62 61 63 6B 75 70 20 70 72 6F 63 65 73 73 20 68 61 73 20 6E 6F 77 20 73 74 61 72 74 65 64 3C 62 72 20}

	condition:
		1 of them
}

rule Zehir_4_asp
{
	meta:
		description = "Semi-Auto-generated  - file Zehir 4.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "7f4e12e159360743ec016273c3b9108c"

	strings:
		$s2 = {3C 2F 61 3E 3C 61 20 68 72 65 66 3D 27 5C 22 26 64 6F 73 79 61 70 61 74 68 26 5C 22 3F 73 74 61 74 75 73 3D 31 30 26 64 50 61 74 68 3D 5C 22 26 66 31 2E 70 61 74 68 26 5C 22 26 70 61 74 68 3D 5C 22 26 70 61 74 68 26 5C 22 26 54 69 6D 65 3D}
		$s4 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 73 75 62 6D 69 74 20 76 61 6C 75 65 3D 5C 22 54 65 73 74 20 45 74 21 5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 22}

	condition:
		1 of them
}

rule sh_php_php
{
	meta:
		description = "Semi-Auto-generated  - file sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "330af9337ae51d0bac175ba7076d6299"

	strings:
		$s1 = {24 61 72 5F 66 69 6C 65 3D 61 72 72 61 79 28 27 2F 65 74 63 2F 70 61 73 73 77 64 27 2C 27 2F 65 74 63 2F 73 68 61 64 6F 77 27 2C 27 2F 65 74 63 2F 6D 61 73 74 65 72 2E 70 61 73 73 77 64 27 2C 27 2F 65 74 63 2F 66 73 74 61 62 27 2C 27 2F 65}
		$s2 = {53 68 6F 77 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 74 65 78 74 20 73 69 7A 65 3D 35 20 76 61 6C 75 65 3D 5C 22 2E 28 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 62 72 5F 73 74 27 5D 29 29 3F 24 5F 50 4F 53 54 5B 27 62 72 5F 73 74 27 5D 3A}

	condition:
		1 of them
}

rule phpbackdoor15_php
{
	meta:
		description = "Semi-Auto-generated  - file phpbackdoor15.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0fdb401a49fc2e481e3dfd697078334b"

	strings:
		$s1 = {65 63 68 6F 20 5C 22 66 69 63 68 69 65 72 20 74 65 6C 65 63 68 61 72 67 65 20 64 61 6E 73 20 5C 22 2E 67 6F 6F 64 5F 6C 69 6E 6B 28 5C 22 2E 2F 5C 22 2E 24 5F 46 49 4C 45 53 5B 5C 22 66 69 63 5C 22 5D 5B 5C 22 6E 61}
		$s2 = {69 66 28 6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 5F 46 49 4C 45 53 5B 5C 22 66 69 63 5C 22 5D 5B 5C 22 74 6D 70 5F 6E 61 6D 65 5C 22 5D 2C 67 6F 6F 64 5F 6C 69 6E 6B 28 5C 22 2E 2F 5C 22 2E 24 5F 46 49}
		$s3 = {65 63 68 6F 20 5C 22 43 6C 69 71 75 65 7A 20 73 75 72 20 75 6E 20 6E 6F 6D 20 64 65 20 66 69 63 68 69 65 72 20 70 6F 75 72 20 6C 61 6E 63 65 72 20 73 6F 6E 20 74 65 6C 65 63 68 61 72 67 65 6D 65 6E 74 2E 20 43 6C 69 71 75 65 7A 20 73}

	condition:
		1 of them
}

rule phpjackal_php
{
	meta:
		description = "Semi-Auto-generated  - file phpjackal.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ab230817bcc99acb9bdc0ec6d264d76f"

	strings:
		$s3 = {24 64 6C 3D 24 5F 52 45 51 55 45 53 54 5B 27 64 6F 77 6E 6C 6F 61 44 27 5D 3B}
		$s4 = {65 6C 73 65 20 73 68 65 6C 4C 28 5C 22 70 65 72 6C 2E 65 78 65 20 24 6E 61 6D 65 20 24 70 6F 72 74 5C 22 29 3B}

	condition:
		1 of them
}

rule sql_php_php
{
	meta:
		description = "Semi-Auto-generated  - file sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8334249cbb969f2d33d678fec2b680c5"

	strings:
		$s1 = {66 70 75 74 73 20 28 24 66 70 2C 20 5C 22 23 20 52 53 54 20 4D 79 53 51 4C 20 74 6F 6F 6C 73 5C 5C 72 5C 5C 6E 23 20 48 6F 6D 65 20 70 61 67 65 3A 20 68 74 74 70 3A 2F 2F 72 73 74 2E 76 6F 69 64 2E 72 75 5C 5C 72 5C 5C 6E 23}
		$s2 = {68 74 74 70 3A 2F 2F 72 73 74 2E 76 6F 69 64 2E 72 75}
		$s3 = {70 72 69 6E 74 20 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 24 5F 53 45 52 56 45 52 5B 50 48 50 5F 53 45 4C 46 5D 3F 73 3D 24 73 26 6C 6F 67 69 6E 3D 24 6C 6F 67 69 6E 26 70 61 73 73 77 64 3D 24 70 61 73 73 77 64 26}

	condition:
		1 of them
}

rule cgi_python_py
{
	meta:
		description = "Semi-Auto-generated  - file cgi-python.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0a15f473e2232b89dae1075e1afdac97"

	strings:
		$s0 = {61 20 43 47 49 20 62 79 20 46 75 7A 7A 79 6D 61 6E}
		$s1 = {5C 22 5C 22 5C 22 2B 66 6F 6E 74 6C 69 6E 65 20 2B 5C 22 56 65 72 73 69 6F 6E 20 3A 20 5C 22 20 2B 20 76 65 72 73 69 6F 6E 73 74 72 69 6E 67 20 2B 20 5C 22 5C 22 5C 22 2C 20 52 75 6E 6E 69 6E 67 20 6F 6E 20 3A 20 5C 22 5C 22 5C 22 20 2B 20}
		$s2 = {76 61 6C 75 65 73 20 3D 20 6D 61 70 28 6C 61 6D 62 64 61 20 78 3A 20 78 2E 76 61 6C 75 65 2C 20 74 68 65 66 6F 72 6D 5B 66 69 65 6C 64 5D 29 20 20 20 20 20 23 20 61 6C 6C 6F 77 73 20 66 6F 72}

	condition:
		1 of them
}

rule ru24_post_sh_php_php
{
	meta:
		description = "Semi-Auto-generated  - file ru24_post_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5b334d494564393f419af745dc1eeec7"

	strings:
		$s1 = {3C 74 69 74 6C 65 3E 52 75 32 34 50 6F 73 74 57 65 62 53 68 65 6C 6C 20 2D 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 2E 5C 22 3C 2F 74 69 74 6C 65 3E}
		$s3 = {69 66 20 28 28 21 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 29 20 7C 7C 20 28 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 3D 5C 22 5C 22 29 29 20 7B 20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 5C 22 69 64 3B 70 77 64 3B 75 6E 61 6D 65 20 2D 61}
		$s4 = {57 72 69 74 65 64 20 62 79 20 44 72 65 41 6D 65 52 7A}

	condition:
		1 of them
}

rule DTool_Pro_php
{
	meta:
		description = "Semi-Auto-generated  - file DTool Pro.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "366ad973a3f327dfbfb915b0faaea5a6"

	strings:
		$s0 = {72 33 76 33 6E 67 34 6E 73 5C 5C 6E 44 69 67 69 74 65}
		$s1 = {69 66 28 21 40 6F 70 65 6E 64 69 72 28 24 63 68 64 69 72 29 29 20 24 63 68 5F 6D 73 67 3D 5C 22 64 74 6F 6F 6C 3A 20 6C 69 6E 65 20 31 3A 20 63 68 64 69 72 3A 20 49 74 20 73 65 65 6D 73 20 74 68 61 74 20 74 68 65 20 70 65 72 6D 69 73 73 69}
		$s3 = {69 66 20 28 65 6D 70 74 79 28 24 63 6D 64 29 20 61 6E 64 20 24 63 68 5F 6D 73 67 3D 3D 5C 22 5C 22 29 20 65 63 68 6F 20 28 5C 22 43 6F 6D 61 6E 64 6F 73 20 45 78 63 6C 75 73 69 76 6F 73 20 64 6F 20 44 54 6F 6F 6C 20 50 72 6F 5C 5C 6E}

	condition:
		1 of them
}

rule telnetd_pl
{
	meta:
		description = "Semi-Auto-generated  - file telnetd.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5f61136afd17eb025109304bd8d6d414"

	strings:
		$s0 = {30 6C 64 57 30 6C 66}
		$s1 = {48 6F 77 65 76 65 72 20 79 6F 75 20 61 72 65 20 6C 75 63 6B 79 20 3A 50}
		$s2 = {49 27 6D 20 46 75 43 4B 65 44}
		$s3 = {69 6F 63 74 6C 28 24 43 4C 49 45 4E 54 7B 24 63 6C 69 65 6E 74 7D 2D 3E 7B 73 68 65 6C 6C 7D 2C 20 26 54 49 4F 43 53 57 49 4E 53 5A 2C 20 24 77 69 6E 73 69 7A 65 29 3B 23}
		$s4 = {61 74 72 69 78 40 69 72 63 2E 62 72 61 73 6E 65 74 2E 6F 72 67}

	condition:
		1 of them
}

rule php_include_w_shell_php
{
	meta:
		description = "Semi-Auto-generated  - file php-include-w-shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "4e913f159e33867be729631a7ca46850"

	strings:
		$s0 = {24 64 61 74 61 6F 75 74 20 2E 3D 20 5C 22 3C 74 64 3E 3C 61 20 68 72 65 66 3D 27 24 4D 79 4C 6F 63 3F 24 53 52 45 51 26 69 6E 63 64 62 68 6F 73 74 3D 24 6D 79 68 6F 73 74 26 69 6E 63 64 62 75 73 65 72 3D 24 6D 79 75 73 65 72 26 69 6E 63 64}
		$s1 = {69 66 28 24 72 75 6E 20 3D 3D 20 31 20 26 26 20 24 70 68 70 73 68 65 6C 6C 61 70 70 20 26 26 20 24 70 68 70 73 68 65 6C 6C 68 6F 73 74 20 26 26 20 24 70 68 70 73 68 65 6C 6C 70 6F 72 74 29 20 24 73 74 72 4F 75 74 70 75 74 20 2E 3D 20 44 42}

	condition:
		1 of them
}

rule Safe0ver_Shell__Safe_Mod_Bypass_By_Evilc0der_php
{
	meta:
		description = "Semi-Auto-generated  - file Safe0ver Shell -Safe Mod Bypass By Evilc0der.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "6163b30600f1e80d2bb5afaa753490b6"

	strings:
		$s0 = {53 61 66 65 30 76 65 72}
		$s1 = {53 63 72 69 70 74 20 47 65 63 69 73 69 20 54 61 6D 61 6D 6C 61 79 61 6D 61 64 69 21}
		$s2 = {64 6F 63 75 6D 65 6E 74 2E 77 72 69 74 65 28 75 6E 65 73 63 61 70 65 28 27 25 33 43 25 36 38 25 37 34 25 36 44 25 36 43 25 33 45 25 33 43 25 36 32 25 36 46 25 36 34 25 37 39 25 33 45 25 33 43 25 35 33 25 34 33 25 35 32 25 34 39 25 35 30 25}

	condition:
		1 of them
}

rule shell_php_php
{
	meta:
		description = "Semi-Auto-generated  - file shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1a95f0163b6dea771da1694de13a3d8d"

	strings:
		$s1 = {2F 2A 20 57 65 20 68 61 76 65 20 66 6F 75 6E 64 20 74 68 65 20 70 61 72 65 6E 74 20 64 69 72 2E 20 57 65 20 6D 75 73 74 20 62 65 20 63 61 72 65 66 75 6C 6C 20 69 66 20 74 68 65 20 70 61 72 65 6E 74 20}
		$s2 = {24 74 6D 70 66 69 6C 65 20 3D 20 74 65 6D 70 6E 61 6D 28 27 2F 74 6D 70 27 2C 20 27 70 68 70 73 68 65 6C 6C 27 29 3B}
		$s3 = {69 66 20 28 65 72 65 67 28 27 5E 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2A 63 64 5B 5B 3A 62 6C 61 6E 6B 3A 5D 5D 2B 28 5B 5E 3B 5D 2B 29 24 27 2C 20 24 63 6F 6D 6D 61 6E 64 2C 20 24 72 65 67 73 29 29 20 7B}

	condition:
		1 of them
}

rule telnet_cgi
{
	meta:
		description = "Semi-Auto-generated  - file telnet.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "dee697481383052980c20c48de1598d1"

	strings:
		$s0 = {77 77 77 2E 72 6F 68 69 74 61 62 2E 63 6F 6D}
		$s1 = {57 20 41 20 52 20 4E 20 49 20 4E 20 47 3A 20 50 72 69 76 61 74 65 20 53 65 72 76 65 72}
		$s2 = {70 72 69 6E 74 20 5C 22 53 65 74 2D 43 6F 6F 6B 69 65 3A 20 53 41 56 45 44 50 57 44 3D 3B 5C 5C 6E 5C 22 3B 20 23 20 72 65 6D 6F 76 65 20 70 61 73 73 77 6F 72 64 20 63 6F 6F 6B 69 65}
		$s3 = {24 50 72 6F 6D 70 74 20 3D 20 24 57 69 6E 4E 54 20 3F 20 5C 22 24 43 75 72 72 65 6E 74 44 69 72 3E 20 5C 22 20 3A 20 5C 22 5B 61 64 6D 69 6E 5C 5C 40 24 53 65 72 76 65 72 4E 61 6D 65 20 24 43}

	condition:
		2 of them
}

rule ironshell_php
{
	meta:
		description = "Semi-Auto-generated  - file ironshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8bfa2eeb8a3ff6afc619258e39fded56"

	strings:
		$s0 = {77 77 77 2E 69 72 6F 6E 77 61 72 65 7A 2E 69 6E 66 6F}
		$s1 = {24 63 6F 6F 6B 69 65 6E 61 6D 65 20 3D 20 5C 22 77 69 65 65 65 65 65 5C 22 3B}
		$s2 = {7E 20 53 68 65 6C 6C 20 49}
		$s3 = {77 77 77 2E 72 6F 6F 74 73 68 65 6C 6C 2D 74 65 61 6D 2E 69 6E 66 6F}
		$s4 = {73 65 74 63 6F 6F 6B 69 65 28 24 63 6F 6F 6B 69 65 6E 61 6D 65 2C 20 24 5F 50 4F 53 54 5B 27 70 61 73 73 27 5D 2C 20 74 69 6D 65 28 29 2B 33 36 30 30 29 3B}

	condition:
		1 of them
}

rule backdoorfr_php
{
	meta:
		description = "Semi-Auto-generated  - file backdoorfr.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "91e4afc7444ed258640e85bcaf0fecfc"

	strings:
		$s1 = {77 77 77 2E 76 69 63 74 69 6D 65 2E 63 6F 6D 2F 69 6E 64 65 78 2E 70 68 70 3F 70 61 67 65 3D 68 74 74 70 3A 2F 2F 65 6D 70 6C 61 63 65 6D 65 6E 74 5F 64 65 5F 6C 61 5F 62 61 63 6B 64 6F 6F 72 2E 70 68 70 20 2C 20 6F 75 20 65 6E 20 74 61 6E}
		$s2 = {70 72 69 6E 74 28 5C 22 3C 62 72 3E 50 72 6F 76 65 6E 61 6E 63 65 20 64 75 20 6D 61 69 6C 20 3A 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 5C 5C 22 74 65 78 74 5C 5C 5C 22 20 6E 61 6D 65 3D 5C 5C 5C 22 70 72 6F 76 65 6E 61 6E 63}

	condition:
		1 of them
}

rule aspydrv_asp
{
	meta:
		description = "Semi-Auto-generated  - file aspydrv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1c01f8a88baee39aa1cebec644bbcb99"
		score = 60

	strings:
		$s0 = {49 66 20 6D 63 6F 6C 46 6F 72 6D 45 6C 65 6D 2E 45 78 69 73 74 73 28 4C 43 61 73 65 28 73 49 6E 64 65 78 29 29 20 54 68 65 6E 20 46 6F 72 6D 20 3D 20 6D 63 6F 6C 46 6F 72 6D 45 6C 65 6D 2E 49 74 65 6D 28 4C 43 61 73 65 28 73 49 6E 64 65 78 29 29}
		$s1 = {70 61 73 73 77 6F 72 64}
		$s2 = {73 65 73 73 69 6F 6E 28 5C 22 73 68 61 67 6D 61 6E 5C 22 29 3D}

	condition:
		2 of them
}

rule cmdjsp_jsp
{
	meta:
		description = "Semi-Auto-generated  - file cmdjsp.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b815611cc39f17f05a73444d699341d4"

	strings:
		$s0 = {2F 2F 20 6E 6F 74 65 20 74 68 61 74 20 6C 69 6E 75 78 20 3D 20 63 6D 64 20 61 6E 64 20 77 69 6E 64 6F 77 73 20 3D 20 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 2B 20 63 6D 64 5C 22 20}
		$s1 = {50 72 6F 63 65 73 73 20 70 20 3D 20 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 5C 22 63 6D 64 2E 65 78 65 20 2F 43 20 5C 22 20 2B 20 63 6D 64 29 3B}
		$s2 = {63 6D 64 6A 73 70 2E 6A 73 70}
		$s3 = {6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67}

	condition:
		2 of them
}

rule h4ntu_shell__powered_by_tsoi_
{
	meta:
		description = "Semi-Auto-generated  - file h4ntu shell [powered by tsoi].txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "06ed0b2398f8096f1bebf092d0526137"

	strings:
		$s0 = {68 34 6E 74 75 20 73 68 65 6C 6C}
		$s1 = {73 79 73 74 65 6D 28 5C 22 24 63 6D 64 20 31 3E 20 2F 74 6D 70 2F 63 6D 64 74 65 6D 70 20 32 3E 26 31 3B 20 63 61 74 20 2F 74 6D 70 2F 63 6D 64 74 65 6D 70 3B 20 72 6D 20 2F 74 6D 70 2F 63 6D 64 74 65 6D 70 5C 22 29 3B}

	condition:
		1 of them
}

rule Ajan_asp
{
	meta:
		description = "Semi-Auto-generated  - file Ajan.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b6f468252407efc2318639da22b08af0"

	strings:
		$s1 = {63 3A 5C 5C 64 6F 77 6E 6C 6F 61 64 65 64 2E 7A 69 70}
		$s2 = {53 65 74 20 65 6E 74 72 69 6B 61 20 3D 20 65 6E 74 72 69 6B 61 2E 43 72 65 61 74 65 54 65 78 74 46 69 6C 65 28 5C 22 63 3A 5C 5C 6E 65 74 2E 76 62 73 5C 22 2C 20 54 72 75 65 29}
		$s3 = {68 74 74 70 3A 2F 2F 77 77 77 33 35 2E 77 65 62 73 61 6D 62 61 2E 63 6F 6D 2F 63 79 62 65 72 76 75 72 67 75 6E 2F}

	condition:
		1 of them
}

rule PHANTASMA_php
{
	meta:
		description = "Semi-Auto-generated  - file PHANTASMA.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "52779a27fa377ae404761a7ce76a5da7"

	strings:
		$s0 = {3E 5B 2A 5D 20 53 61 66 65 6D 6F 64 65 20 4D 6F 64 65 20 52 75 6E 3C 2F 44 49 56 3E}
		$s1 = {24 66 69 6C 65 31 20 2D 20 24 66 69 6C 65 32 20 2D 20 3C 61 20 68 72 65 66 3D 24 53 43 52 49 50 54 5F 4E 41 4D 45 3F 24 51 55 45 52 59 5F 53 54 52 49 4E 47 26 73 65 65 3D 24 66 69 6C 65 3E 24 66 69 6C 65 3C 2F 61 3E 3C 62 72 3E}
		$s2 = {5B 2A 5D 20 53 70 61 77 6E 69 6E 67 20 53 68 65 6C 6C}
		$s3 = {43 68 61 30 73}

	condition:
		2 of them
}

rule MySQL_Web_Interface_Version_0_8_php
{
	meta:
		description = "Semi-Auto-generated  - file MySQL Web Interface Version 0.8.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "36d4f34d0a22080f47bb1cb94107c60f"

	strings:
		$s0 = {53 6F 6F 4D 69 6E 20 4B 69 6D}
		$s1 = {68 74 74 70 3A 2F 2F 70 6F 70 65 79 65 2E 73 6E 75 2E 61 63 2E 6B 72 2F 7E 73 6D 6B 69 6D 2F 6D 79 73 71 6C}
		$s2 = {68 72 65 66 3D 27 24 50 48 50 5F 53 45 4C 46 3F 61 63 74 69 6F 6E 3D 64 72 6F 70 46 69 65 6C 64 26 64 62 6E 61 6D 65 3D 24 64 62 6E 61 6D 65 26 74 61 62 6C 65 6E 61 6D 65 3D 24 74 61 62 6C 65 6E 61 6D 65}
		$s3 = {3C 74 68 3E 54 79 70 65 3C 2F 74 68 3E 3C 74 68 3E 26 6E 62 73 70 4D 26 6E 62 73 70 3C 2F 74 68 3E 3C 74 68 3E 26 6E 62 73 70 44 26 6E 62 73 70 3C 2F 74 68 3E 3C 74 68 3E 75 6E 73 69 67 6E 65 64 3C 2F 74 68 3E 3C 74 68 3E 7A 65 72 6F 66 69}

	condition:
		2 of them
}

rule simple_cmd_html
{
	meta:
		description = "Semi-Auto-generated  - file simple_cmd.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c6381412df74dbf3bcd5a2b31522b544"

	strings:
		$s1 = {3C 74 69 74 6C 65 3E 47 2D 53 65 63 75 72 69 74 79 20 57 65 62 73 68 65 6C 6C 3C 2F 74 69 74 6C 65 3E}
		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 54 45 58 54 20 6E 61 6D 65 3D 5C 22 2D 63 6D 64 5C 22 20 73 69 7A 65 3D 36 34 20 76 61 6C 75 65 3D 5C 22 3C 3F 3D 24 63 6D 64 3F 3E 5C 22 20}
		$s3 = {3C 3F 20 69 66 28 24 63 6D 64 20 21 3D 20 5C 22 5C 22 29 20 70 72 69 6E 74 20 53 68 65 6C 6C 5F 45 78 65 63 28 24 63 6D 64 29 3B 3F 3E}
		$s4 = {3C 3F 20 24 63 6D 64 20 3D 20 24 5F 52 45 51 55 45 53 54 5B 5C 22 2D 63 6D 64 5C 22 5D 3B 3F 3E}

	condition:
		all of them
}

rule multiple_webshells_0001
{
	meta:
		description = "Semi-Auto-generated  - from files 1.txt, c2007.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_1_c2007_php_php_c100_php"
		hash0 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash1 = "d089e7168373a0634e1ac18c0ee00085"
		hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"

	strings:
		$s0 = {65 63 68 6F 20 5C 22 3C 62 3E 43 68 61 6E 67 69 6E 67 20 66 69 6C 65 2D 6D 6F 64 65 20 28 5C 22 2E 24 64 2E 24 66 2E 5C 22 29 2C 20 5C 22 2E 76 69 65 77 5F 70 65 72 6D 73 5F 63 6F 6C 6F 72 28 24 64 2E 24 66 29 2E 5C 22 20 28 5C 22}
		$s3 = {65 63 68 6F 20 5C 22 3C 74 64 3E 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 5C 22 2E 24 73 71 6C 5F 73 75 72 6C 2E 5C 22 73 71 6C 5F 61 63 74 3D 71 75 65 72 79 26 73 71 6C 5F 71 75 65 72 79 3D 5C 22 2E 75 72}

	condition:
		1 of them
}

rule multiple_webshells_0002
{
	meta:
		description = "Semi-Auto-generated  - from files nst.php.php.txt, img.php.php.txt, nstview.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_nst_php_php_img_php_php_nstview_php_php"
		hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
		hash1 = "17a07bb84e137b8aa60f87cd6bfab748"
		hash2 = "4745d510fed4378e4b1730f56f25e569"

	strings:
		$s0 = {3C 74 72 3E 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 70 6F 73 74 3E 3C 74 64 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 3C 62 3E 42 61 63 6B 20 63 6F 6E 6E 65 63 74 3A 3C 2F 62 3E 3C 2F 66 6F 6E 74 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69}
		$s1 = {24 70 65 72 6C 5F 70 72 6F 78 79 5F 73 63 70 20 3D 20 5C 22 49 79 45 76 64 58 4E 79 4C 32 4A 70 62 69 39 77 5A 58 4A 73 49 43 41 4E 43 69 4D 68 4C 33 56 7A 63 69 39 31 63 32 4D 76 63 47 56 79 62 43 38 31 4C 6A 41 77 4E 43 39 69 61 57 34 76}
		$s2 = {3C 74 72 3E 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 70 6F 73 74 3E 3C 74 64 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 3C 62 3E 42 61 63 6B 64 6F 6F 72 3A 3C 2F 62 3E 3C 2F 66 6F 6E 74 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74}

	condition:
		1 of them
}

rule multiple_webshells_0003
{
	meta:
		description = "Semi-Auto-generated  - from files network.php.php.txt, xinfo.php.php.txt, nfm.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_network_php_php_xinfo_php_php_nfm_php_php"
		hash0 = "acdbba993a5a4186fd864c5e4ea0ba4f"
		hash1 = "2601b6fc1579f263d2f3960ce775df70"
		hash2 = "401fbae5f10283051c39e640b77e4c26"

	strings:
		$s0 = {2E 74 65 78 74 62 6F 78 20 7B 20 62 61 63 6B 67 72 6F 75 6E 64 3A 20 57 68 69 74 65 3B 20 62 6F 72 64 65 72 3A 20 31 70 78 20 23 30 30 30 30 30 30 20 73 6F 6C 69 64 3B 20 63 6F 6C 6F 72 3A 20 23 30 30 30 30 39 39 3B 20 66 6F 6E 74 2D 66 61}
		$s2 = {3C 69 6E 70 75 74 20 63 6C 61 73 73 3D 27 69 6E 70 75 74 62 6F 78 27 20 74 79 70 65 3D 27 74 65 78 74 27 20 6E 61 6D 65 3D 27 70 61 73 73 5F 64 65 27 20 73 69 7A 65 3D 35 30 20 6F 6E 63 6C 69 63 6B 3D 74 68 69 73 2E 76 61 6C 75 65 3D 27 27}

	condition:
		all of them
}

rule multiple_webshells_0004
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s2 = {65 63 68 6F 20 5C 22 3C 68 72 20 73 69 7A 65 3D 5C 5C 5C 22 31 5C 5C 5C 22 20 6E 6F 73 68 61 64 65 3E 3C 62 3E 44 6F 6E 65 21 3C 2F 62 3E 3C 62 72 3E 54 6F 74 61 6C 20 74 69 6D 65 20 28 73 65 63 73 2E 29 3A 20 5C 22 2E 24 66 74}
		$s3 = {24 66 71 62 5F 6C 6F 67 20 2E 3D 20 5C 22 5C 5C 72 5C 5C 6E 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 5C 5C 72 5C 5C 6E 44 6F 6E 65 21 5C 5C 72}

	condition:
		1 of them
}

rule multiple_webshells_0005
{
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash3 = "8023394542cddf8aee5dec6072ed02b5"
		hash4 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash5 = "817671e1bdc85e04cc3440bbd9288800"

	strings:
		$s2 = {27 65 6E 67 5F 74 65 78 74 37 31 27 3D 3E 5C 22 53 65 63 6F 6E 64 20 63 6F 6D 6D 61 6E 64 73 20 70 61 72 61 6D 20 69 73 3A 5C 5C 72 5C 5C 6E 2D 20 66 6F 72 20 43 48 4F 57 4E 20 2D 20 6E 61 6D 65 20 6F 66 20 6E 65 77 20 6F 77 6E 65 72 20 6F}
		$s4 = {69 66 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 73 5F 6D 61 73 6B 27 5D 29 20 26 26 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 6D 27 5D 29 29 20 7B 20 24 73 72 20 3D 20 6E 65 77 20 53 65 61 72 63 68 52 65 73 75 6C 74}

	condition:
		1 of them
}

rule multiple_webshells_0006
{
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, ctt_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_c99shell_v1_0_php_php_c99php_SsEs_php_php_ctt_sh_php_php"
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash3 = "671cad517edd254352fe7e0c7c981c39"

	strings:
		$s0 = {5C 22 41 41 41 41 41 43 48 35 42 41 45 41 41 41 6B 41 4C 41 41 41 41 41 41 55 41 42 51 41 41 41 52 30 4D 4D 6C 4A 71 79 7A 46 61 6C 71 45 51 4A 75 47 45 51 53 43 6E 57 67 36 46 6F 67 70 6B 48 41 4D 46 34 48 41 4A 73 57 68 37 2F 7A 65 5C 22}
		$s2 = {5C 22 6D 54 50 2F 7A 44 50 2F 2F 32 59 41 41 47 59 41 4D 32 59 41 5A 6D 59 41 6D 57 59 41 7A 47 59 41 2F 32 59 7A 41 47 59 7A 4D 32 59 7A 5A 6D 59 7A 6D 57 59 7A 7A 47 59 7A 2F 32 5A 6D 41 47 5A 6D 4D 32 5A 6D 5A 6D 5A 6D 6D 57 5A 6D 5C 22}
		$s4 = {5C 22 52 30 6C 47 4F 44 6C 68 46 41 41 55 41 4B 4C 2F 41 50 2F 34 2F 38 44 41 77 48 39 2F 41 50 2F 34 41 4C 2B 2F 76 77 41 41 41 41 41 41 41 41 41 41 41 43 48 35 42 41 45 41 41 41 45 41 4C 41 41 41 41 41 41 55 41 42 51 41 51 41 4D 6F 5C 22}

	condition:
		2 of them
}

rule multiple_webshells_0007
{
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash2 = "817671e1bdc85e04cc3440bbd9288800"

	strings:
		$s2 = {65 63 68 6F 20 24 74 65 2E 5C 22 3C 64 69 76 20 61 6C 69 67 6E 3D 63 65 6E 74 65 72 3E 3C 74 65 78 74 61 72 65 61 20 63 6F 6C 73 3D 33 35 20 6E 61 6D 65 3D 64 62 5F 71 75 65 72 79 3E 5C 22 2E 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27}
		$s3 = {65 63 68 6F 20 73 72 28 34 35 2C 5C 22 3C 62 3E 5C 22 2E 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74 38 30 27 5D 2E 24 61 72 72 6F 77 2E 5C 22 3C 2F 62 3E 5C 22 2C 5C 22 3C 73 65 6C 65 63 74 20 6E 61 6D 65 3D 64 62 3E}

	condition:
		1 of them
}

rule multiple_webshells_0008
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt, ctt_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php_ctt_sh_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash5 = "09609851caa129e40b0d56e90dfc476c"
		hash6 = "671cad517edd254352fe7e0c7c981c39"

	strings:
		$s0 = {20 20 69 66 20 28 24 63 6F 70 79 5F 75 6E 73 65 74 29 20 7B 66 6F 72 65 61 63 68 28 24 73 65 73 73 5F 64 61 74 61 5B 5C 22 63 6F 70 79 5C 22 5D 20 61 73 20 24 6B 3D 3E 24 76 29 20 7B 75 6E 73 65 74 28 24 73 65 73 73 5F 64 61 74 61 5B 5C 22}
		$s1 = {20 20 69 66 20 28 66 69 6C 65 5F 65 78 69 73 74 73 28 24 6D 6B 66 69 6C 65 29 29 20 7B 65 63 68 6F 20 5C 22 3C 62 3E 4D 61 6B 65 20 46 69 6C 65 20 5C 5C 5C 22 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 6D 6B 66 69 6C 65}
		$s2 = {20 20 65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 62 3E 4D 79 53 51 4C 20 5C 22 2E 6D 79 73 71 6C 5F 67 65 74 5F 73 65 72 76 65 72 5F 69 6E 66 6F 28 29 2E 5C 22 20 28 70 72 6F 74 6F 20 76 2E 5C 22 2E 6D 79 73 71 6C 5F 67 65 74 5F 70 72}
		$s3 = {20 20 65 6C 73 65 69 66 20 28 21 66 6F 70 65 6E 28 24 6D 6B 66 69 6C 65 2C 5C 22 77 5C 22 29 29 20 7B 65 63 68 6F 20 5C 22 3C 62 3E 4D 61 6B 65 20 46 69 6C 65 20 5C 5C 5C 22 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 6D}

	condition:
		all of them
}

rule multiple_webshells_0009
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash5 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = {24 73 65 73 73 5F 64 61 74 61 5B 5C 22 63 75 74 5C 22 5D 20 3D 20 61 72 72 61 79 28 29 3B 20 63 39 39 5F 73}
		$s3 = {69 66 20 28 28 21 65 72 65 67 69 28 5C 22 68 74 74 70 3A 2F 2F 5C 22 2C 24 75 70 6C 6F 61 64 75 72 6C 29 29 20 61 6E 64 20 28 21 65 72 65 67 69 28 5C 22 68 74 74 70 73 3A 2F 2F 5C 22 2C 24 75 70 6C 6F 61 64 75 72 6C 29 29}

	condition:
		1 of them
}

rule multiple_webshells_0010
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_wacking_php_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = {5C 22 3C 74 64 3E 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 5C 22 2E 24 73 71 6C 5F 73 75 72 6C 2E 5C 22 73 71 6C 5F 61 63 74 3D 71 75 65 72 79 26 73 71 6C 5F 71 75 65 72 79 3D 5C 22 2E 75 72}
		$s2 = {63 39 39 73 68 5F 73 71 6C 71 75 65 72 79}

	condition:
		1 of them
}

rule multiple_webshells_0011
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash4 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = {65 6C 73 65 20 7B 24 61 63 74 20 3D 20 5C 22 66 5C 22 3B 20 24 64 20 3D 20 64 69 72 6E 61 6D 65 28 24 6D 6B 66 69 6C 65 29 3B 20 69 66 20 28 73 75 62 73 74 72 28 24 64 2C 2D 31 29 20 21 3D 20 44 49 52 45 43 54 4F 52 59 5F 53 45 50 41}
		$s3 = {65 6C 73 65 20 7B 65 63 68 6F 20 5C 22 3C 62 3E 46 69 6C 65 20 5C 5C 5C 22 5C 22 2E 24 73 71 6C 5F 67 65 74 66 69 6C 65 2E 5C 22 5C 5C 5C 22 3A 3C 2F 62 3E 3C 62 72 3E 5C 22 2E 6E 6C 32 62 72 28 68 74 6D 6C 73 70 65 63}

	condition:
		1 of them
}

rule multiple_webshells_0012
{
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash4 = "817671e1bdc85e04cc3440bbd9288800"

	strings:
		$s0 = {65 63 68 6F 20 73 72 28 31 35 2C 5C 22 3C 62 3E 5C 22 2E 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74}
		$s1 = {2E 24 61 72 72 6F 77 2E 5C 22 3C 2F 62 3E 5C 22 2C 69 6E 28 27 74 65 78 74 27 2C 27}

	condition:
		2 of them
}

rule multiple_webshells_0013
{
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"

	strings:
		$s0 = {27 72 75 5F 74 65 78 74 39 27 20 3D 3E 27 3F 3F 3F 3F 3F 3F 3F 3F 20 3F 3F 3F 3F 3F 20 3F 20 3F 3F 3F 3F 3F 3F 3F 3F 20 3F 3F 3F 20 3F 20 2F 62 69 6E 2F 62 61 73 68 27 2C}
		$s1 = {24 6E 61 6D 65 3D 27 65 63 33 37 31 37 34 38 64 63 32 64 61 36 32 34 62 33 35 61 34 66 38 66 36 38 35 64 64 31 32 32 27}
		$s2 = {72 73 74 2E 76 6F 69 64 2E 72 75}

	condition:
		3 of them
}

rule multiple_webshells_0014
{
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_r57_Shell_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "8023394542cddf8aee5dec6072ed02b5"
		hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash3 = "817671e1bdc85e04cc3440bbd9288800"

	strings:
		$s0 = {65 63 68 6F 20 77 73 28 32 29 2E 24 6C 62 2E 5C 22 20 3C 61}
		$s1 = {24 73 71 6C 20 3D 20 5C 22 4C 4F 41 44 20 44 41 54 41 20 49 4E 46 49 4C 45 20 5C 5C 5C 22 5C 22 2E 24 5F 50 4F 53 54 5B 27 74 65 73 74 33 5F 66 69 6C 65 27 5D}
		$s3 = {69 66 20 28 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 29 26 26 21 24 73 61 66 65 5F 6D 6F 64 65 29 20 7B 20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 28 24 77 69 6E 64 6F 77 73 29 3F 28 5C 22 64 69 72 5C 22 29 3A 28 5C 22 6C}

	condition:
		2 of them
}

rule multiple_webshells_0015
{
	meta:
		description = "Semi-Auto-generated  - from files wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_wacking_php_php_1_SpecialShell_99_php_php_c100_php"
		hash0 = "9c5bb5e3a46ec28039e8986324e42792"
		hash1 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash2 = "09609851caa129e40b0d56e90dfc476c"
		hash3 = "38fd7e45f9c11a37463c3ded1c76af4c"

	strings:
		$s0 = {69 66 28 65 72 65 67 69 28 5C 22 2E 2F 73 68 62 64 20 24 70 6F 72 5C 22 2C 24 73 63 61 6E 29 29}
		$s1 = {24 5F 50 4F 53 54 5B 27 62 61 63 6B 63 6F 6E 6E 65 63 74 69 70 27 5D}
		$s2 = {24 5F 50 4F 53 54 5B 27 62 61 63 6B 63 63 6F 6E 6E 6D 73 67 27 5D}

	condition:
		1 of them
}

rule multiple_webshells_0016
{
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash2 = "8023394542cddf8aee5dec6072ed02b5"
		hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash4 = "817671e1bdc85e04cc3440bbd9288800"

	strings:
		$s1 = {69 66 28 72 6D 64 69 72 28 24 5F 50 4F 53 54 5B 27 6D 6B 5F 6E 61 6D 65 27 5D 29 29}
		$s2 = {24 72 20 2E 3D 20 27 3C 74 72 3E 3C 74 64 3E 27 2E 77 73 28 33 29 2E 27 3C 66 6F 6E 74 20 66 61 63 65 3D 56 65 72 64 61 6E 61 20 73 69 7A 65 3D 2D 32 3E 3C 62 3E 27 2E 24 6B 65 79 2E 27 3C 2F 62 3E 3C 2F 66 6F 6E 74 3E 3C 2F 74 64 3E}
		$s3 = {69 66 28 75 6E 6C 69 6E 6B 28 24 5F 50 4F 53 54 5B 27 6D 6B 5F 6E 61 6D 65 27 5D 29 29 20 65 63 68 6F 20 5C 22 3C 74 61 62 6C 65 20 77 69 64 74 68 3D 31 30 30 25 20 63 65 6C 6C 70 61 64 64 69 6E 67 3D 30 20 63 65 6C 6C}

	condition:
		2 of them
}

rule multiple_webshells_0017
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash3 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = {5C 22 65 78 74 5F 61 76 69 5C 22 3D 3E 61 72 72 61 79 28 5C 22 65 78 74 5F 61 76 69 5C 22 2C 5C 22 65 78 74 5F 6D 6F 76 5C 22 2C 5C 22 65 78 74 5F 6D 76 69}
		$s1 = {65 63 68 6F 20 5C 22 3C 62 3E 45 78 65 63 75 74 65 20 66 69 6C 65 3A 3C 2F 62 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 5C 22 2E 24 73 75 72 6C 2E 5C 22 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 50 4F 53 54 3E 3C 69 6E 70 75}
		$s2 = {5C 22 65 78 74 5F 68 74 61 63 63 65 73 73 5C 22 3D 3E 61 72 72 61 79 28 5C 22 65 78 74 5F 68 74 61 63 63 65 73 73 5C 22 2C 5C 22 65 78 74 5F 68 74 70 61 73 73 77 64}

	condition:
		1 of them
}

rule multiple_webshells_0018
{
	meta:
		description = "Semi-Auto-generated  - from files webadmin.php.php.txt, iMHaPFtp.php.php.txt, Private-i3lue.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_webadmin_php_php_iMHaPFtp_php_php_Private_i3lue_php"
		hash0 = "b268e6fa3bf3fe496cffb4ea574ec4c7"
		hash1 = "12911b73bc6a5d313b494102abcf5c57"
		hash2 = "13f5c7a035ecce5f9f380967cf9d4e92"

	strings:
		$s0 = {72 65 74 75 72 6E 20 24 74 79 70 65 20 2E 20 24 6F 77 6E 65 72 20 2E 20 24 67 72 6F 75 70 20 2E 20 24 6F 74 68 65 72 3B}
		$s1 = {24 6F 77 6E 65 72 20 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 34 30 30 29 20 3F 20 27 72 27 20 3A 20 27 2D 27 3B}

	condition:
		all of them
}

rule multiple_php_webshells
{
	meta:
		description = "Semi-Auto-generated  - from files multiple_php_webshells"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "be0f67f3e995517d18859ed57b4b4389"
		hash3 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash4 = "8023394542cddf8aee5dec6072ed02b5"
		hash5 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash6 = "817671e1bdc85e04cc3440bbd9288800"
		hash7 = "7101fe72421402029e2629f3aaed6de7"
		hash8 = "f618f41f7ebeb5e5076986a66593afd1"
		score = 75

	strings:
		$s0 = {6B 56 79 63 6D 39 79 4F 69 41 6B 49 56 78 75 49 69 6B 37 44 51 70 6A 62 32 35 75 5A 57 4E 30 4B 46 4E 50 51 30 74 46 56 43 77 67 4A 48 42 68 5A 47 52 79 4B 53 42 38 66 43 42 6B 61 57 55 6F 49 6B 56 79 63 6D 39 79 4F 69 41 6B 49 56 78 75 49}
		$s2 = {73 4E 43 69 52 77 63 6D 39 30 62 7A 31 6E 5A 58 52 77 63 6D 39 30 62 32 4A 35 62 6D 46 74 5A 53 67 6E 64 47 4E 77 4A 79 6B 37 44 51 70 7A 62 32 4E 72 5A 58 51 6F 55 30 39 44 53 30 56 55 4C 43 42 51 52 6C 39 4A 54 6B 56 55 4C 43 42 54 54 30}
		$s4 = {41 38 63 33 6C 7A 4C 33 4E 76 59 32 74 6C 64 43 35 6F 50 67 30 4B 49 32 6C 75 59 32 78 31 5A 47 55 67 50 47 35 6C 64 47 6C 75 5A 58 51 76 61 57 34 75 61 44 34 4E 43 69 4E 70 62 6D 4E 73 64 57 52 6C 49 44 78 6C 63 6E 4A 75 62 79 35 6F 50 67}

	condition:
		2 of them
}

rule multiple_webshells_0019
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"

	strings:
		$s0 = {3C 62 3E 44 75 6D 70 65 64 21 20 44 75 6D 70 20 68 61 73 20 62 65 65 6E 20 77 72 69 74 65 64 20 74 6F 20}
		$s1 = {69 66 20 28 28 21 65 6D 70 74 79 28 24 64 6F 6E 61 74 65 64 5F 68 74 6D 6C 29 29 20 61 6E 64 20 28 69 6E 5F 61 72 72 61 79 28 24 61 63 74 2C 24 64 6F 6E 61 74 65 64 5F 61 63 74 29 29 29 20 7B 65 63 68 6F 20 5C 22 3C 54 41 42 4C 45 20 73 74}
		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 73 75 62 6D 69 74 20 6E 61 6D 65 3D 61 63 74 61 72 63 62 75 66 66 20 76 61 6C 75 65 3D 5C 5C 5C 22 50 61 63 6B 20 62 75 66 66 65 72 20 74 6F 20 61 72 63 68 69 76 65}

	condition:
		1 of them
}

rule multiple_webshells_0020
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"

	strings:
		$s0 = {40 69 6E 69 5F 73 65 74 28 5C 22 68 69 67 68 6C 69 67 68 74}
		$s1 = {65 63 68 6F 20 5C 22 3C 62 3E 52 65 73 75 6C 74 20 6F 66 20 65 78 65 63 75 74 69 6F 6E 20 74 68 69 73 20 50 48 50 2D 63 6F 64 65 3C 2F 62 3E 3A 3C 62 72 3E 5C 22 3B}
		$s2 = {7B 24 72 6F 77 5B 5D 20 3D 20 5C 22 3C 62 3E 4F 77 6E 65 72 2F 47 72 6F 75 70 3C 2F 62 3E 5C 22 3B 7D}

	condition:
		2 of them
}

rule multiple_webshells_0021
{
	meta:
		description = "Semi-Auto-generated  - from files GFS web-shell ver 3.1.7 - PRiV8.php.txt, nshell.php.php.txt, gfs_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_GFS_web_shell_ver_3_1_7___PRiV8_php_nshell_php_php_gfs_sh_php_php"
		hash0 = "be0f67f3e995517d18859ed57b4b4389"
		hash1 = "4a44d82da21438e32d4f514ab35c26b6"
		hash2 = "f618f41f7ebeb5e5076986a66593afd1"

	strings:
		$s2 = {65 63 68 6F 20 24 75 6E 61 6D 65 2E 5C 22 3C 2F 66 6F 6E 74 3E 3C 62 72 3E 3C 62 3E 5C 22 3B}
		$s3 = {77 68 69 6C 65 28 21 66 65 6F 66 28 24 66 29 29 20 7B 20 24 72 65 73 2E 3D 66 72 65 61 64 28 24 66 2C 31 30 32 34 29 3B 20 7D}
		$s4 = {65 63 68 6F 20 5C 22 75 73 65 72 3D 5C 22 2E 40 67 65 74 5F 63 75 72 72 65 6E 74 5F 75 73 65 72 28 29 2E 5C 22 20 75 69 64 3D 5C 22 2E 40 67 65 74 6D 79 75 69 64 28 29 2E 5C 22 20 67 69 64 3D 5C 22 2E 40 67 65 74 6D 79 67 69 64 28 29}

	condition:
		2 of them
}

rule multiple_webshells_0022
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = {63 39 39 66 74 70 62 72 75 74 65 63 68 65 63 6B}
		$s1 = {24 66 74 70 71 75 69 63 6B 5F 74 20 3D 20 72 6F 75 6E 64 28 67 65 74 6D 69 63 72 6F 74 69 6D 65 28 29 2D 24 66 74 70 71 75 69 63 6B 5F 73 74 2C 34 29 3B}
		$s2 = {24 66 71 62 5F 6C 65 6E 67 68 74 20 3D 20 24 6E 69 78 70 77 64 70 65 72 70 61 67 65 3B}
		$s3 = {24 73 6F 63 6B 20 3D 20 40 66 74 70 5F 63 6F 6E 6E 65 63 74 28 24 68 6F 73 74 2C 24 70 6F 72 74 2C 24 74 69 6D 65 6F 75 74 29 3B}

	condition:
		2 of them
}

rule multiple_webshells_0023
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash3 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash4 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = {24 73 71 6C 71 75 69 63 6B 6C 61 75 6E 63 68 5B 5D 20 3D 20 61 72 72 61 79 28 5C 22}
		$s1 = {65 6C 73 65 20 7B 65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 62 3E 46 69 6C 65 20 64 6F 65 73 20 6E 6F 74 20 65 78 69 73 74 73 20 28 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 64 2E 24 66 29 2E 5C 22 29 21 3C}

	condition:
		all of them
}

rule multiple_webshells_0024
{
	meta:
		description = "Semi-Auto-generated  - from files antichat.php.php.txt, Fatalshell.php.php.txt, a_gedit.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_antichat_php_php_Fatalshell_php_php_a_gedit_php_php"
		hash0 = "128e90b5e2df97e21e96d8e268cde7e3"
		hash1 = "b15583f4eaad10a25ef53ab451a4a26d"
		hash2 = "ab9c6b24ca15f4a1b7086cad78ff0f78"

	strings:
		$s0 = {69 66 28 40 24 5F 50 4F 53 54 5B 27 73 61 76 65 27 5D 29 77 72 69 74 65 66 28 24 66 69 6C 65 2C 24 5F 50 4F 53 54 5B 27 64 61 74 61 27 5D 29 3B}
		$s1 = {69 66 28 24 61 63 74 69 6F 6E 3D 3D 5C 22 70 68 70 65 76 61 6C 5C 22 29 7B}
		$s2 = {24 75 70 6C 6F 61 64 66 69 6C 65 20 3D 20 24 64 69 72 75 70 6C 6F 61 64 2E 5C 22 2F 5C 22 2E 24 5F 50 4F 53 54 5B 27 66 69 6C 65 6E 61 6D 65 27 5D 3B}
		$s3 = {24 64 69 72 3D 67 65 74 63 77 64 28 29 2E 5C 22 2F 5C 22 3B}

	condition:
		2 of them
}

rule multiple_webshells_0025
{
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_c99shell_v1_0_php_php_c99php_SsEs_php_php"
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"

	strings:
		$s3 = {69 66 20 28 21 65 6D 70 74 79 28 24 64 65 6C 65 72 72 29 29 20 7B 65 63 68 6F 20 5C 22 3C 62 3E 44 65 6C 65 74 69 6E 67 20 77 69 74 68 20 65 72 72 6F 72 73 3A 3C 2F 62 3E 3C 62 72 3E 5C 22 2E 24 64 65 6C 65 72 72 3B 7D}

	condition:
		1 of them
}

rule multiple_webshells_0026
{
	meta:
		description = "Semi-Auto-generated  - from files Crystal.php.txt, nshell.php.php.txt, load_shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_Crystal_php_nshell_php_php_load_shell_php_php"
		hash0 = "fdbf54d5bf3264eb1c4bff1fac548879"
		hash1 = "4a44d82da21438e32d4f514ab35c26b6"
		hash2 = "0c5d227f4aa76785e4760cdcff78a661"

	strings:
		$s0 = {69 66 20 28 24 66 69 6C 65 6E 61 6D 65 20 21 3D 20 5C 22 2E 5C 22 20 61 6E 64 20 24 66 69 6C 65 6E 61 6D 65 20 21 3D 20 5C 22 2E 2E 5C 22 29 7B}
		$s1 = {24 64 69 72 65 73 20 3D 20 24 64 69 72 65 73 20 2E 20 24 64 69 72 65 63 74 6F 72 79 3B}
		$s4 = {24 61 72 72 20 3D 20 61 72 72 61 79 5F 6D 65 72 67 65 28 24 61 72 72 2C 20 67 6C 6F 62 28 5C 22 2A 5C 22 29 29 3B}

	condition:
		2 of them
}

rule multiple_webshells_0027
{
	meta:
		description = "Semi-Auto-generated  - from files nst.php.php.txt, cybershell.php.php.txt, img.php.php.txt, nstview.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_nst_php_php_cybershell_php_php_img_php_php_nstview_php_php"
		hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
		hash1 = "ef8828e0bc0641a655de3932199c0527"
		hash2 = "17a07bb84e137b8aa60f87cd6bfab748"
		hash3 = "4745d510fed4378e4b1730f56f25e569"

	strings:
		$s0 = {40 24 72 74 6F 3D 24 5F 50 4F 53 54 5B 27 72 74 6F 27 5D 3B}
		$s2 = {53 43 52 4F 4C 4C 42 41 52 2D 54 52 41 43 4B 2D 43 4F 4C 4F 52 3A 20 23 39 31 41 41 46 46}
		$s3 = {24 74 6F 31 3D 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 2F 2F 5C 22 2C 5C 22 2F 5C 22 2C 24 74 6F 31 29 3B}

	condition:
		2 of them
}

rule multiple_webshells_0028
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, dC3 Security Crew Shell PRiV.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_dC3_Security_Crew_Shell_PRiV_php_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "433706fdc539238803fd47c4394b5109"
		hash4 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = {20 69 66 20 28 24 6D 6F 64 65 20 26 20 30 78 32 30 30 29 20 7B 24 77 6F 72 6C 64 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 77 6F 72 6C 64 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 3D 20 5C 22 78 5C 22 29 3F 5C 22 74 5C 22 3A}
		$s1 = {20 24 67 72 6F 75 70 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 30 31 30 29 3F 5C 22 78 5C 22 3A 5C 22 2D 5C 22 3B}

	condition:
		all of them
}

rule multiple_webshells_0029
{
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, 1.txt, c2007.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_c99shell_v1_0_php_php_c99php_1_c2007_php_php_c100_php"
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash3 = "d089e7168373a0634e1ac18c0ee00085"
		hash4 = "38fd7e45f9c11a37463c3ded1c76af4c"

	strings:
		$s0 = {24 72 65 73 75 6C 74 20 3D 20 6D 79 73 71 6C 5F 71 75 65 72 79 28 5C 22 53 48 4F 57 20 50 52 4F 43 45 53 53 4C 49 53 54 5C 22 2C 20 24 73 71 6C 5F 73 6F 63 6B 29 3B 20}

	condition:
		all of them
}

rule multiple_php_webshells_2
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt, ctt_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash5 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash6 = "09609851caa129e40b0d56e90dfc476c"
		hash7 = "671cad517edd254352fe7e0c7c981c39"

	strings:
		$s0 = {65 6C 73 65 69 66 20 28 21 65 6D 70 74 79 28 24 66 74 29 29 20 7B 65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 62 3E 4D 61 6E 75 61 6C 6C 79 20 73 65 6C 65 63 74 65 64 20 74 79 70 65 20 69 73 20 69 6E 63 6F 72 72 65 63 74 2E 20 49}
		$s1 = {65 6C 73 65 20 7B 65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 62 3E 55 6E 6B 6E 6F 77 6E 20 65 78 74 65 6E 73 69 6F 6E 20 28 5C 22 2E 24 65 78 74 2E 5C 22 29 2C 20 70 6C 65 61 73 65 2C 20 73 65 6C 65 63 74 20 74 79 70 65 20 6D 61}
		$s3 = {24 73 20 3D 20 5C 22 21 5E 28 5C 22 2E 69 6D 70 6C 6F 64 65 28 5C 22 7C 5C 22 2C 24 74 6D 70 29 2E 5C 22 29 24 21 69 5C 22 3B}

	condition:
		all of them
}

rule multiple_webshells_0030
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_1_SpecialShell_99_php_php"
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash4 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = {69 66 20 28 24 74 6F 74 61 6C 20 3D 3D 3D 20 46 41 4C 53 45 29 20 7B 24 74 6F 74 61 6C 20 3D 20 30 3B 7D}
		$s1 = {24 66 72 65 65 5F 70 65 72 63 65 6E 74 20 3D 20 72 6F 75 6E 64 28 31 30 30 2F 28 24 74 6F 74 61 6C 2F 24 66 72 65 65 29 2C 32 29 3B}
		$s2 = {69 66 20 28 21 24 62 6F 6F 6C 29 20 7B 24 62 6F 6F 6C 20 3D 20 69 73 5F 64 69 72 28 24 6C 65 74 74 65 72 2E 5C 22 3A 5C 5C 5C 5C 5C 22 29 3B 7D}
		$s3 = {24 62 6F 6F 6C 20 3D 20 24 69 73 64 69 73 6B 65 74 74 65 20 3D 20 69 6E 5F 61 72 72 61 79 28 24 6C 65 74 74 65 72 2C 24 73 61 66 65 6D 6F 64 65 5F 64 69 73 6B 65 74 74 65 73 29 3B}

	condition:
		2 of them
}

rule multiple_webshells_0031
{
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_r577_php_php_r57_php_php_spy_php_php_s_php_php"
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash3 = "817671e1bdc85e04cc3440bbd9288800"

	strings:
		$s0 = {24 72 65 73 20 3D 20 6D 73 73 71 6C 5F 71 75 65 72 79 28 5C 22 73 65 6C 65 63 74 20 2A 20 66 72 6F 6D 20 72 35 37 5F 74 65 6D 70 5F 74 61 62 6C 65 5C 22 2C 24 64 62 29 3B}
		$s2 = {27 65 6E 67 5F 74 65 78 74 33 30 27 3D 3E 27 43 61 74 20 66 69 6C 65 27 2C}
		$s3 = {40 6D 73 73 71 6C 5F 71 75 65 72 79 28 5C 22 64 72 6F 70 20 74 61 62 6C 65 20 72 35 37 5F 74 65 6D 70 5F 74 61 62 6C 65 5C 22 2C 24 64 62 29 3B}

	condition:
		1 of them
}

rule multiple_webshells_0032
{
	meta:
		description = "Semi-Auto-generated  - from files nixrem.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		was = "_nixrem_php_php_c99shell_v1_0_php_php_c99php_NIX_REMOTE_WEB_SHELL_v_0_5_alpha_Lite_Public_Version_php"
		hash0 = "40a3e86a63d3d7f063a86aab5b5f92c6"
		hash1 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash2 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash3 = "f3ca29b7999643507081caab926e2e74"

	strings:
		$s0 = {24 6E 75 6D 20 3D 20 24 6E 69 78 70 61 73 73 77 64 20 2B 20 24 6E 69 78 70 77 64 70 65 72 70 61 67 65 3B}
		$s1 = {24 72 65 74 20 3D 20 70 6F 73 69 78 5F 6B 69 6C 6C 28 24 70 69 64 2C 24 73 69 67 29 3B}
		$s2 = {69 66 20 28 24 75 69 64 29 20 7B 65 63 68 6F 20 6A 6F 69 6E 28 5C 22 3A 5C 22 2C 24 75 69 64 29 2E 5C 22 3C 62 72 3E 5C 22 3B 7D}
		$s3 = {24 69 20 3D 20 24 6E 69 78 70 61 73 73 77 64 3B}

	condition:
		2 of them
}

rule DarkSecurityTeam_Webshell
{
	meta:
		description = "Dark Security Team Webshell"
		author = "Florian Roth"
		hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
		score = 50

	strings:
		$s0 = {66 6F 72 6D 20 6D 65 74 68 6F 64 3D 70 6F 73 74 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 68 69 64 64 65 6E 20 6E 61 6D 65 3D 5C 22 5C 22 23 5C 22 5C 22 20 76 61 6C 75 65 3D 45 78 65 63 75 74 65 28 53 65 73 73 69 6F 6E 28 5C 22 5C 22 23 5C 22 5C 22 29 29 3E 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 74 68 65 50 61 74 68 20 76 61 6C 75 65 3D 5C 22 5C 22 5C 22 26 48 74 6D 6C 45 6E 63 6F 64 65 28 53 65 72 76 65 72 2E 4D 61 70 50 61 74 68 28 5C 22 2E 5C 22 29 29 26}

	condition:
		1 of them
}

rule PHP_Cloaked_Webshell_SuperFetchExec
{
	meta:
		description = "Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC"
		reference = "http://goo.gl/xFvioC"
		author = "Florian Roth"
		score = 50

	strings:
		$s0 = {65 6C 73 65 7B 24 64 2E 3D 40 63 68 72 28 28 24 68 5B 24 65 5B 24 6F 5D 5D 3C 3C 34 29 2B 28 24 68 5B 24 65 5B 2B 2B 24 6F 5D 5D 29 29 3B 7D 7D 65 76 61 6C 28 24 64 29 3B}

	condition:
		$s0
}

rule WebShell_RemExp_asp_php
{
	meta:
		description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
		author = "Florian Roth"
		hash = "d9919dcf94a70d5180650de8b81669fa1c10c5a2"

	strings:
		$s0 = {6C 73 45 78 74 20 3D 20 52 69 67 68 74 28 46 69 6C 65 4E 61 6D 65 2C 20 4C 65 6E 28 46 69 6C 65 4E 61 6D 65 29 20 2D 20 6C 69 43 6F 75 6E 74 29}
		$s7 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 74 69 74 6C 65 3D 5C 22 3C 25 3D 46 69 6C 65 2E 4E 61 6D 65 25 3E 5C 22 3E 20 3C 61 20 68 72 65 66 3D 20 5C 22 73 68 6F 77 63 6F 64 65 2E 61 73 70 3F 66}
		$s13 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 44 72 69 76 65 2E 53 68 61 72 65 4E 61 6D 65 20 26 20 5C 22 20 5B 73 68 61 72 65 5D 5C 22}
		$s19 = {49 66 20 52 65 71 75 65 73 74 2E 51 75 65 72 79 53 74 72 69 6E 67 28 5C 22 43 6F 70 79 46 69 6C 65 5C 22 29 20 3C 3E 20 5C 22 5C 22 20 54 68 65 6E}
		$s20 = {3C 74 64 20 77 69 64 74 68 3D 5C 22 34 30 25 5C 22 20 68 65 69 67 68 74 3D 5C 22 32 30 5C 22 20 62 67 63 6F 6C 6F 72 3D 5C 22 73 69 6C 76 65 72 5C 22 3E 20 20 4E 61 6D 65 3C 2F 74 64 3E}

	condition:
		all of them
}

rule WebShell_dC3_Security_Crew_Shell_PRiV
{
	meta:
		description = "PHP Webshells Github Archive - file dC3_Security_Crew_Shell_PRiV.php"
		author = "Florian Roth"
		hash = "1b2a4a7174ca170b4e3a8cdf4814c92695134c8a"

	strings:
		$s0 = {40 72 6D 64 69 72 28 24 5F 47 45 54 5B 27 66 69 6C 65 27 5D 29 20 6F 72 20 64 69 65 20 28 5C 22 5B 2D 5D 45 72 72 6F 72 20 64 65 6C 65 74 69 6E 67 20 64 69 72 21 5C 22 29 3B}
		$s4 = {24 70 73 3D 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 22 2C 5C 22 2F 5C 22 2C 67 65 74 65 6E 76 28 27 44 4F 43 55 4D 45 4E 54 5F 52 4F 4F 54 27 29 29 3B}
		$s5 = {68 65 61 64 65 72 28 5C 22 45 78 70 69 72 65 73 3A 20 5C 22 2E 64 61 74 65 28 5C 22 72 5C 22 2C 6D 6B 74 69 6D 65 28 30 2C 30 2C 30 2C 31 2C 31 2C 32 30 33 30 29 29 29 3B}
		$s15 = {73 65 61 72 63 68 5F 66 69 6C 65 28 24 5F 50 4F 53 54 5B 27 73 65 61 72 63 68 27 5D 2C 75 72 6C 64 65 63 6F 64 65 28 24 5F 50 4F 53 54 5B 27 64 69 72 27 5D 29 29 3B}
		$s16 = {65 63 68 6F 20 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 24 69 6D 61 67 65 73 5B 24 5F 47 45 54 5B 27 70 69 63 27 5D 5D 29 3B}
		$s20 = {69 66 20 28 69 73 73 65 74 28 24 5F 47 45 54 5B 27 72 65 6E 61 6D 65 5F 61 6C 6C 27 5D 29 29 20 7B}

	condition:
		3 of them
}

rule WebShell_simattacker
{
	meta:
		description = "PHP Webshells Github Archive - file simattacker.php"
		author = "Florian Roth"
		hash = "258297b62aeaf4650ce04642ad5f19be25ec29c9"

	strings:
		$s1 = {24 66 72 6F 6D 20 3D 20 72 61 6E 64 20 28 37 31 2C 31 30 32 30 30 30 30 30 30 30 29 2E 5C 22 40 5C 22 2E 5C 22 41 74 74 61 63 6B 65 72 2E 63 6F 6D 5C 22 3B}
		$s4 = {26 6E 62 73 70 3B 54 75 72 6B 69 73 68 20 48 61 63 6B 65 72 73 20 3A 20 57 57 57 2E 41 4C 54 55 52 4B 53 2E 43 4F 4D 20 3C 62 72 3E}
		$s5 = {26 6E 62 73 70 3B 50 72 6F 67 72 61 6D 65 72 20 3A 20 53 69 6D 41 74 74 61 63 6B 65 72 20 2D 20 45 64 69 74 65 64 20 42 79 20 4B 69 6E 67 44 65 66 61 63 65 72 3C 62 72 3E}
		$s6 = {2F 2F 66 61 6B 65 20 6D 61 69 6C 20 3D 20 55 73 65 20 76 69 63 74 69 6D 20 73 65 72 76 65 72 20 34 20 44 4F 53 20 2D 20 66 61 6B 65 20 6D 61 69 6C 20}
		$s10 = {26 6E 62 73 70 3B 65 2D 6D 61 69 6C 20 3A 20 6B 69 6E 67 64 65 66 61 63 65 72 40 6D 73 6E 2E 63 6F 6D 3C 62 72 3E}
		$s17 = {65 72 72 6F 72 5F 72 65 70 6F 72 74 69 6E 67 28 45 5F 45 52 52 4F 52 20 7C 20 45 5F 57 41 52 4E 49 4E 47 20 7C 20 45 5F 50 41 52 53 45 29 3B}
		$s18 = {65 63 68 6F 20 5C 22 3C 66 6F 6E 74 20 73 69 7A 65 3D 27 31 27 20 63 6F 6C 6F 72 3D 27 23 39 39 39 39 39 39 27 3E 44 6F 6E 74 20 69 6E 20 77 69 6E 64 6F 77 73 5C 22 3B}
		$s20 = {24 43 6F 6D 6D 65 6E 74 73 3D 24 5F 50 4F 53 54 5B 27 43 6F 6D 6D 65 6E 74 73 27 5D 3B}

	condition:
		2 of them
}

rule WebShell_DTool_Pro
{
	meta:
		description = "PHP Webshells Github Archive - file DTool Pro.php"
		author = "Florian Roth"
		hash = "e2ee1c7ba7b05994f65710b7bbf935954f2c3353"

	strings:
		$s1 = {66 75 6E 63 74 69 6F 6E 20 50 48 50 67 65 74 28 29 7B 69 6E 63 6C 56 61 72 28 29 3B 20 69 66 28 63 6F 6E 66 69 72 6D 28 5C 22 4F 20 50 48 50 67 65 74 20 61 67 6F 72 61 20 6F 66 65 72 65 63 65 20 75 6D 61 20 6C 69 73 74 61 20 70 72 6F 6E 74}
		$s2 = {3C 66 6F 6E 74 20 73 69 7A 65 3D 33 3E 62 79 20 72 33 76 33 6E 67 34 6E 73 20 2D 20 72 65 76 65 6E 67 61 6E 73 40 67 6D 61 69 6C 2E 63 6F 6D 20 3C 2F 66 6F 6E 74 3E}
		$s3 = {66 75 6E 63 74 69 6F 6E 20 50 48 50 77 72 69 74 65 72 28 29 7B 69 6E 63 6C 56 61 72 28 29 3B 76 61 72 20 75 72 6C 3D 70 72 6F 6D 70 74 28 5C 22 5B 20 50 48 50 77 72 69 74 65 72 20 5D 20 62 79 20 72 33 76 33 6E 67 34 6E 73 5C 5C 6E 44 69 67}
		$s11 = {2F 2F 54 75 72 6E 73 20 74 68 65 20 27 6C 73 27 20 63 6F 6D 6D 61 6E 64 20 6D 6F 72 65 20 75 73 65 66 75 6C 6C 2C 20 73 68 6F 77 69 6E 67 20 69 74 20 61 73 20 69 74 20 6C 6F 6F 6B 73 20 69 6E 20 74 68 65 20 73 68 65 6C 6C}
		$s13 = {69 66 20 28 40 66 69 6C 65 5F 65 78 69 73 74 73 28 5C 22 2F 75 73 72 2F 62 69 6E 2F 77 67 65 74 5C 22 29 29 20 24 70 72 6F 33 3D 5C 22 3C 69 3E 77 67 65 74 3C 2F 69 3E 20 61 74 20 2F 75 73 72 2F 62 69 6E 2F 77 67 65 74 2C 20 5C 22 3B}
		$s14 = {2F 2F 54 6F 20 6B 65 65 70 20 74 68 65 20 63 68 61 6E 67 65 73 20 69 6E 20 74 68 65 20 75 72 6C 2C 20 77 68 65 6E 20 75 73 69 6E 67 20 74 68 65 20 27 47 45 54 27 20 77 61 79 20 74 6F 20 73 65 6E 64 20 70 68 70 20 76 61 72 69 61 62 6C 65 73}
		$s16 = {66 75 6E 63 74 69 6F 6E 20 50 48 50 66 28 29 7B 69 6E 63 6C 56 61 72 28 29 3B 76 61 72 20 6F 3D 70 72 6F 6D 70 74 28 5C 22 5B 20 50 48 50 66 69 6C 45 64 69 74 6F 72 20 5D 20 62 79 20 72 33 76 33 6E 67 34 6E 73 5C 5C 6E 44 69 67 69 74 65 20}
		$s18 = {69 66 28 65 6D 70 74 79 28 24 66 75 29 29 20 24 66 75 20 3D 20 40 24 5F 47 45 54 5B 27 66 75 27 5D 3B}

	condition:
		3 of them
}

rule WebShell_ironshell
{
	meta:
		description = "PHP Webshells Github Archive - file ironshell.php"
		author = "Florian Roth"
		hash = "d47b8ba98ea8061404defc6b3a30839c4444a262"

	strings:
		$s0 = {3C 74 69 74 6C 65 3E 27 2E 67 65 74 65 6E 76 28 5C 22 48 54 54 50 5F 48 4F 53 54 5C 22 29 2E 27 20 7E 20 53 68 65 6C 6C 20 49 3C 2F 74 69 74 6C 65 3E}
		$s2 = {24 6C 69 6E 6B 20 3D 20 6D 79 73 71 6C 5F 63 6F 6E 6E 65 63 74 28 24 5F 50 4F 53 54 5B 27 68 6F 73 74 27 5D 2C 20 24 5F 50 4F 53 54 5B 27 75 73 65 72 6E 61 6D 65 27 5D 2C 20 24 5F 50 4F 53 54}
		$s4 = {65 72 72 6F 72 5F 72 65 70 6F 72 74 69 6E 67 28 30 29 3B 20 2F 2F 49 66 20 74 68 65 72 65 20 69 73 20 61 6E 20 65 72 72 6F 72 2C 20 77 65 27 6C 6C 20 73 68 6F 77 20 69 74 2C 20 6B 3F}
		$s8 = {70 72 69 6E 74 20 5C 22 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 5C 22 2E 24 6D 65 2E 5C 22 3F 70 3D 63 68 6D 6F 64 26 66 69 6C 65 3D 5C 22 2E 24 63 6F 6E 74 65 6E 74 2E 5C 22 26 64}
		$s15 = {69 66 28 21 69 73 5F 6E 75 6D 65 72 69 63 28 24 5F 50 4F 53 54 5B 27 74 69 6D 65 6C 69 6D 69 74 27 5D 29 29}
		$s16 = {69 66 28 24 5F 50 4F 53 54 5B 27 63 68 61 72 73 27 5D 20 3D 3D 20 5C 22 39 39 39 39 5C 22 29}
		$s17 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 61 7A 5C 5C 5C 22 3E 61 20 2D 20 7A 7A 7A 7A 7A 3C 2F 6F 70 74 69 6F 6E 3E}
		$s18 = {70 72 69 6E 74 20 73 68 65 6C 6C 5F 65 78 65 63 28 24 63 6F 6D 6D 61 6E 64 29 3B}

	condition:
		3 of them
}

rule WebShell_indexer_asp_php
{
	meta:
		description = "PHP Webshells Github Archive - file indexer.asp.php.txt"
		author = "Florian Roth"
		hash = "e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d"

	strings:
		$s0 = {3C 6D 65 74 61 20 68 74 74 70 2D 65 71 75 69 76 3D 5C 22 43 6F 6E 74 65 6E 74 2D 4C 61 6E 67 75 61 67 65 5C 22 20 63 6F 6E 74 65 6E 74 3D 5C 22 74 72 5C 22 3E}
		$s1 = {3C 74 69 74 6C 65 3E 57 77 57 2E 53 61 4E 61 4C 54 65 52 6F 52 2E 4F 72 47 20 2D 20 69 6E 44 45 58 45 52 20 41 6E 64 20 52 65 61 44 65 72 3C 2F 74 69 74 6C 65 3E}
		$s2 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 22 3F 47 6F 6E 64 65 72 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 70 6F 73 74 5C 22 3E}
		$s4 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 22 3F 6F 6B 75 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 70 6F 73 74 5C 22 3E}
		$s7 = {76 61 72 20 6D 65 73 73 61 67 65 3D 5C 22 53 61 4E 61 4C 54 65 52 6F 52 20 2D 20}
		$s8 = {6E 44 65 78 45 72 20 2D 20 52 65 61 64 65 72 5C 22}

	condition:
		3 of them
}

rule WebShell_toolaspshell
{
	meta:
		description = "PHP Webshells Github Archive - file toolaspshell.php"
		author = "Florian Roth"
		hash = "11d236b0d1c2da30828ffd2f393dd4c6a1022e3f"

	strings:
		$s0 = {63 70 72 74 68 74 6D 6C 20 3D 20 5C 22 3C 66 6F 6E 74 20 66 61 63 65 3D 27 61 72 69 61 6C 27 20 73 69 7A 65 3D 27 31 27 3E 52 48 54 4F 4F 4C 53 20 31 2E 35 20 42 45 54 41 28 50 56 54 29 20 45 64 69 74 65 64 20 42 79 20 4B 69 6E 67 44 65 66}
		$s12 = {62 61 72 72 61 70 6F 73 20 3D 20 43 49 6E 74 28 49 6E 73 74 72 52 65 76 28 4C 65 66 74 28 72 61 69 7A 2C 4C 65 6E 28 72 61 69 7A 29 20 2D 20 31 29 2C 5C 22 5C 5C 5C 22 29 29 20 2D 20 31}
		$s20 = {64 65 73 74 69 6E 6F 33 20 3D 20 66 6F 6C 64 65 72 49 74 65 6D 2E 70 61 74 68 20 26 20 5C 22 5C 5C 69 6E 64 65 78 2E 61 73 70 5C 22}

	condition:
		2 of them
}

rule WebShell_b374k_mini_shell_php_php
{
	meta:
		description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
		author = "Florian Roth"
		hash = "afb88635fbdd9ebe86b650cc220d3012a8c35143"

	strings:
		$s0 = {40 65 72 72 6F 72 5F 72 65 70 6F 72 74 69 6E 67 28 30 29 3B}
		$s2 = {40 65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 24 63 6F 64 65 29 29 29 3B}
		$s3 = {40 73 65 74 5F 74 69 6D 65 5F 6C 69 6D 69 74 28 30 29 3B 20}

	condition:
		all of them
}

rule WebShell_Sincap_1_0
{
	meta:
		description = "PHP Webshells Github Archive - file Sincap 1.0.php"
		author = "Florian Roth"
		hash = "9b72635ff1410fa40c4e15513ae3a496d54f971c"

	strings:
		$s4 = {3C 2F 66 6F 6E 74 3E 3C 2F 73 70 61 6E 3E 3C 61 20 68 72 65 66 3D 5C 22 6D 61 69 6C 74 6F 3A 73 68 6F 70 65 6E 40 61 76 65 6E 74 67 72 75 70 2E 6E 65 74 5C 22 3E}
		$s5 = {3C 74 69 74 6C 65 3E 3A 3A 20 41 76 65 6E 74 47 72 75 70 20 3A 3A 2E 2E 20 2D 20 53 69 6E 63 61 70 20 31 2E 30 20 7C 20 53 65 73 73 69 6F 6E 28 4F 74 75 72 75 6D 29 20 42}
		$s9 = {3C 2F 73 70 61 6E 3E 41 76 72 61 73 79 61 20 56 65 72 69 20 76 65 20 4E 65 74 57 6F 72 6B 20 54 65 6B 6E 6F 6C 6F 6A 69 6C 65 72 69 20 47 65 6C 69}
		$s12 = {77 68 69 6C 65 20 28 28 24 65 6B 69 6E 63 69 3D 72 65 61 64 64 69 72 20 28 24 73 65 64 61 74 29 29 29 7B}
		$s19 = {24 64 65 67 65 72 32 3D 20 5C 22 24 69 63 68 5B 24 74 61 6D 70 6F 6E 34 5D 5C 22 3B}

	condition:
		2 of them
}

rule WebShell_b374k_php
{
	meta:
		description = "PHP Webshells Github Archive - file b374k.php.php"
		author = "Florian Roth"
		hash = "04c99efd187cf29dc4e5603c51be44170987bce2"

	strings:
		$s0 = {2F 2F 20 65 6E 63 72 79 70 74 20 79 6F 75 72 20 70 61 73 73 77 6F 72 64 20 74 6F 20 6D 64 35 20 68 65 72 65 20 68 74 74 70 3A 2F 2F 6B 65 72 69 6E 63 69 2E 6E 65 74 2F 3F 78 3D 64 65 63 6F 64 65}
		$s6 = {2F 2F 20 70 61 73 73 77 6F 72 64 20 28 64 65 66 61 75 6C 74 20 69 73 3A 20 62 33 37 34 6B 29}
		$s8 = {2F 2F 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A 2A}
		$s9 = {2F 2F 20 62 33 37 34 6B 20 32 2E 32}
		$s10 = {65 76 61 6C 28 5C 22 3F 3E 5C 22 2E 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28}

	condition:
		3 of them
}

rule WebShell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend
{
	meta:
		description = "PHP Webshells Github Archive - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
		author = "Florian Roth"
		hash = "6454cc5ab73143d72cf0025a81bd1fe710351b44"

	strings:
		$s4 = {26 6E 62 73 70 3B 49 72 61 6E 69 61 6E 20 48 61 63 6B 65 72 73 20 3A 20 57 57 57 2E 53 49 4D 4F 52 47 48 2D 45 56 2E 43 4F 4D 20 3C 62 72 3E}
		$s5 = {2F 2F 66 61 6B 65 20 6D 61 69 6C 20 3D 20 55 73 65 20 76 69 63 74 69 6D 20 73 65 72 76 65 72 20 34 20 44 4F 53 20 2D 20 66 61 6B 65 20 6D 61 69 6C 20}
		$s10 = {3C 61 20 73 74 79 6C 65 3D 5C 22 54 45 58 54 2D 44 45 43 4F 52 41 54 49 4F 4E 3A 20 6E 6F 6E 65 5C 22 20 68 72 65 66 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 73 69 6D 6F 72 67 68 2D 65 76 2E 63 6F 6D 5C 22 3E}
		$s16 = {65 72 72 6F 72 5F 72 65 70 6F 72 74 69 6E 67 28 45 5F 45 52 52 4F 52 20 7C 20 45 5F 57 41 52 4E 49 4E 47 20 7C 20 45 5F 50 41 52 53 45 29 3B}
		$s17 = {65 63 68 6F 20 5C 22 3C 66 6F 6E 74 20 73 69 7A 65 3D 27 31 27 20 63 6F 6C 6F 72 3D 27 23 39 39 39 39 39 39 27 3E 44 6F 6E 74 20 69 6E 20 77 69 6E 64 6F 77 73 5C 22 3B}
		$s19 = {24 43 6F 6D 6D 65 6E 74 73 3D 24 5F 50 4F 53 54 5B 27 43 6F 6D 6D 65 6E 74 73 27 5D 3B}
		$s20 = {56 69 63 74 69 6D 20 4D 61 69 6C 20 3A 3C 62 72 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 27 74 65 78 74 27 20 6E 61 6D 65 3D 27 74 6F 27 20 3E 3C 62 72 3E}

	condition:
		3 of them
}

rule WebShell_h4ntu_shell__powered_by_tsoi_
{
	meta:
		description = "PHP Webshells Github Archive - file h4ntu shell [powered by tsoi].php"
		author = "Florian Roth"
		hash = "cbca8cd000e705357e2a7e0cf8262678706f18f9"

	strings:
		$s11 = {3C 74 69 74 6C 65 3E 68 34 6E 74 75 20 73 68 65 6C 6C 20 5B 70 6F 77 65 72 65 64 20 62 79 20 74 73 6F 69 5D 3C 2F 74 69 74 6C 65 3E}
		$s13 = {24 63 6D 64 20 3D 20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3B}
		$s16 = {24 75 6E 61 6D 65 20 3D 20 70 6F 73 69 78 5F 75 6E 61 6D 65 28 20 29 3B}
		$s17 = {69 66 28 21 24 77 68 6F 61 6D 69 29 24 77 68 6F 61 6D 69 3D 65 78 65 63 28 5C 22 77 68 6F 61 6D 69 5C 22 29 3B}
		$s18 = {65 63 68 6F 20 5C 22 3C 70 3E 3C 66 6F 6E 74 20 73 69 7A 65 3D 32 20 66 61 63 65 3D 56 65 72 64 61 6E 61 3E 3C 62 3E 54 68 69 73 20 49 73 20 54 68 65 20 53 65 72 76 65 72 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 3C 2F 62 3E 3C 2F 66 6F 6E 74 3E}
		$s20 = {6F 62 5F 65 6E 64 5F 63 6C 65 61 6E 28 29 3B}

	condition:
		3 of them
}

rule WebShell_php_webshells_MyShell
{
	meta:
		description = "PHP Webshells Github Archive - file MyShell.php"
		author = "Florian Roth"
		hash = "42e283c594c4d061f80a18f5ade0717d3fb2f76d"

	strings:
		$s3 = {3C 74 69 74 6C 65 3E 4D 79 53 68 65 6C 6C 20 65 72 72 6F 72 20 2D 20 41 63 63 65 73 73 20 44 65 6E 69 65 64 3C 2F 74 69 74 6C 65 3E}
		$s4 = {24 61 64 6D 69 6E 45 6D 61 69 6C 20 3D 20 5C 22 79 6F 75 72 65 6D 61 69 6C 40 79 6F 75 72 73 65 72 76 65 72 2E 63 6F 6D 5C 22 3B}
		$s5 = {2F 2F 41 20 77 6F 72 6B 64 69 72 20 68 61 73 20 62 65 65 6E 20 61 73 6B 65 64 20 66 6F 72 20 2D 20 77 65 20 63 68 64 69 72 20 74 6F 20 74 68 61 74 20 64 69 72 2E}
		$s6 = {73 79 73 74 65 6D 28 24 63 6F 6D 6D 61 6E 64 20 2E 20 5C 22 20 31 3E 20 2F 74 6D 70 2F 6F 75 74 70 75 74 2E 74 78 74 20 32 3E 26 31 3B 20 63 61 74 20 2F 74 6D 70 2F 6F 75 74 70 75 74 2E 74 78 74 3B 20 72 6D 20 2F 74 6D 70 2F 6F}
		$s13 = {23 24 61 75 74 6F 45 72 72 6F 72 54 72 61 70 20 45 6E 61 62 6C 65 20 61 75 74 6F 6D 61 74 69 63 20 65 72 72 6F 72 20 74 72 61 70 69 6E 67 20 69 66 20 63 6F 6D 6D 61 6E 64 20 72 65 74 75 72 6E 73 20 65 72 72 6F 72 2E}
		$s14 = {2F 2A 20 4E 6F 20 77 6F 72 6B 5F 64 69 72 20 2D 20 77 65 20 63 68 64 69 72 20 74 6F 20 24 44 4F 43 55 4D 45 4E 54 5F 52 4F 4F 54 20 2A 2F}
		$s19 = {23 65 76 65 72 79 20 63 6F 6D 6D 61 6E 64 20 79 6F 75 20 65 78 63 65 63 75 74 65 2E}
		$s20 = {3C 66 6F 72 6D 20 6E 61 6D 65 3D 5C 22 73 68 65 6C 6C 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 70 6F 73 74 5C 22 3E}

	condition:
		3 of them
}

rule WebShell_php_webshells_pws
{
	meta:
		description = "PHP Webshells Github Archive - file pws.php"
		author = "Florian Roth"
		hash = "7a405f1c179a84ff8ac09a42177a2bcd8a1a481b"

	strings:
		$s6 = {69 66 20 28 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 29 7B}
		$s7 = {24 63 6D 64 20 3D 20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3B}
		$s10 = {65 63 68 6F 20 5C 22 46 49 4C 45 20 55 50 4C 4F 41 44 45 44 20 54 4F 20 24 64 65 7A 5C 22 3B}
		$s11 = {69 66 20 28 66 69 6C 65 5F 65 78 69 73 74 73 28 24 75 70 6C 6F 61 64 65 64 29 29 20 7B}
		$s12 = {63 6F 70 79 28 24 75 70 6C 6F 61 64 65 64 2C 20 24 64 65 7A 29 3B}
		$s17 = {70 61 73 73 74 68 72 75 28 24 63 6D 64 29 3B}

	condition:
		4 of them
}

rule WebShell_reader_asp_php
{
	meta:
		description = "PHP Webshells Github Archive - file reader.asp.php.txt"
		author = "Florian Roth"
		hash = "70656f3495e2b3ad391a77d5208eec0fb9e2d931"

	strings:
		$s5 = {73 74 65 72 5C 22 20 6E 61 6D 65 3D 73 75 62 6D 69 74 3E 20 3C 2F 46 6F 6E 74 3E 20 26 6E 62 73 70 3B 20 26 6E 62 73 70 3B 20 26 6E 62 73 70 3B 20 3C 61 20 68 72 65 66 3D 6D 61 69 6C 74 6F 3A 6D 61 69 6C 62 6F 6D 62 40 68 6F 74 6D 61 69 6C}
		$s12 = {20 48 41 43 4B 49 4E 47 20}
		$s16 = {46 4F 4E 54 2D 57 45 49 47 48 54 3A 20 62 6F 6C 64 3B 20 42 41 43 4B 47 52 4F 55 4E 44 3A 20 23 66 66 66 66 66 66 20 75 72 6C 28 27 69 6D 61 67 65 73 2F 63 65 6C 6C 70 69 63 31 2E 67 69 66 27 29 3B 20 54 45 58 54 2D 49 4E 44 45 4E 54 3A 20}
		$s20 = {50 41 44 44 49 4E 47 2D 52 49 47 48 54 3A 20 38 70 78 3B 20 50 41 44 44 49 4E 47 2D 4C 45 46 54 3A 20 38 70 78 3B 20 46 4F 4E 54 2D 57 45 49 47 48 54 3A 20 62 6F 6C 64 3B 20 46 4F 4E 54 2D 53 49 5A 45 3A 20 31 31 70 78 3B 20 42 41 43 4B 47}

	condition:
		3 of them
}

rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2
{
	meta:
		description = "PHP Webshells Github Archive - file Safe_Mode_Bypass_PHP_4.4.2_and_PHP_5.1.2.php"
		author = "Florian Roth"
		hash = "db076b7c80d2a5279cab2578aa19cb18aea92832"

	strings:
		$s1 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 3E 47 65 74 20 2F 65 74 63 2F 70 61 73 73 77 64 3C 2F 6F 70 74 69 6F 6E 3E}
		$s6 = {62 79 20 50 48 50 20 45 6D 70 65 72 6F 72 3C 78 62 35 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D 3E}
		$s9 = {5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 66 69 6C 65 29 2E 5C 22 20 68 61 73 20 62 65 65 6E 20 61 6C 72 65 61 64 79 20 6C 6F 61 64 65 64 2E 20 50 48 50 20 45 6D 70 65 72 6F 72 20 3C 78 62 35 40 68 6F 74 6D 61 69 6C 2E}
		$s11 = {64 69 65 28 5C 22 3C 46 4F 4E 54 20 43 4F 4C 4F 52 3D 5C 5C 5C 22 52 45 44 5C 5C 5C 22 3E 3C 43 45 4E 54 45 52 3E 53 6F 72 72 79 2E 2E 2E 20 46 69 6C 65}
		$s15 = {69 66 28 65 6D 70 74 79 28 24 5F 47 45 54 5B 27 66 69 6C 65 27 5D 29 29 7B}
		$s16 = {65 63 68 6F 20 5C 22 3C 68 65 61 64 3E 3C 74 69 74 6C 65 3E 53 61 66 65 20 4D 6F 64 65 20 53 68 65 6C 6C 3C 2F 74 69 74 6C 65 3E 3C 2F 68 65 61 64 3E 5C 22 3B 20}

	condition:
		3 of them
}

rule WebShell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit
{
	meta:
		description = "PHP Webshells Github Archive - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
		author = "Florian Roth"
		hash = "b2b797707e09c12ff5e632af84b394ad41a46fa4"

	strings:
		$s4 = {24 6C 69 7A 30 7A 69 6D 3D 73 68 65 6C 6C 5F 65 78 65 63 28 24 5F 50 4F 53 54 5B 6C 69 7A 30 5D 29 3B 20}
		$s6 = {24 6C 69 7A 30 3D 73 68 65 6C 6C 5F 65 78 65 63 28 24 5F 50 4F 53 54 5B 62 61 62 61 5D 29 3B 20}
		$s9 = {65 63 68 6F 20 5C 22 3C 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 62 6C 75 65 3E 4C 69 7A 30 7A 69 4D 20 50 72 69 76 61 74 65 20 53 61 66 65 20 4D 6F 64 65 20 43 6F 6D 6D 61 6E 64 20 45 78 65 63 75 72 69 74 6F 6E 20 42 79 70 61 73 73 20 45}
		$s12 = {20 3A 3D 29 20 3A 3C 2F 66 6F 6E 74 3E 3C 73 65 6C 65 63 74 20 73 69 7A 65 3D 5C 22 31 5C 22 20 6E 61 6D 65 3D 5C 22 6C 69 7A 30 5C 22 3E}
		$s13 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 63 61 74 20 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 3E 2F 65 74 63 2F 70 61 73 73 77 64 3C 2F 6F 70 74 69 6F 6E 3E}

	condition:
		1 of them
}

rule WebShell_php_backdoor
{
	meta:
		description = "PHP Webshells Github Archive - file php-backdoor.php"
		author = "Florian Roth"
		hash = "b190c03af4f3fb52adc20eb0f5d4d151020c74fe"

	strings:
		$s5 = {68 74 74 70 3A 2F 2F 3C 3F 20 65 63 68 6F 20 24 53 45 52 56 45 52 5F 4E 41 4D 45 2E 24 52 45 51 55 45 53 54 5F 55 52 49 3B 20 3F 3E 3F 64 3D 2F 65 74 63 20 6F 6E 20 2A 6E 69 78}
		$s6 = {2F 2F 20 61 20 73 69 6D 70 6C 65 20 70 68 70 20 62 61 63 6B 64 6F 6F 72 20 7C 20 63 6F 64 65 64 20 62 79 20 7A 30 6D 62 69 65 20 5B 33 30 2E 30 38 2E 30 33 5D 20 7C 20 68 74 74 70 3A 2F 2F 66 72 65 65 6E 65 74 2E 61 6D 2F 7E 7A 6F 6D 62 69}
		$s11 = {69 66 28 21 69 73 73 65 74 28 24 5F 52 45 51 55 45 53 54 5B 27 64 69 72 27 5D 29 29 20 64 69 65 28 27 68 65 79 2C 73 70 65 63 69 66 79 20 64 69 72 65 63 74 6F 72 79 21 27 29 3B}
		$s13 = {65 6C 73 65 20 65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 27 24 50 48 50 5F 53 45 4C 46 3F 66 3D 24 64 2F 24 64 69 72 27 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 62 6C 61 63 6B 3E 5C 22 3B}
		$s15 = {3C 70 72 65 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 22 3C 3F 20 65 63 68 6F 20 24 50 48 50 5F 53 45 4C 46 3B 20 3F 3E 5C 22 20 4D 45 54 48 4F 44 3D 47 45 54 20 3E 65 78 65 63 75 74 65 20 63 6F 6D 6D 61 6E 64 3A 20 3C 69 6E 70 75 74 20}

	condition:
		1 of them
}

rule WebShell_Worse_Linux_Shell
{
	meta:
		description = "PHP Webshells Github Archive - file Worse Linux Shell.php"
		author = "Florian Roth"
		hash = "64623ab1246bc8f7d256b25f244eb2b41f543e96"

	strings:
		$s4 = {69 66 28 20 24 5F 50 4F 53 54 5B 27 5F 61 63 74 27 5D 20 3D 3D 20 5C 22 55 70 6C 6F 61 64 21 5C 22 20 29 20 7B}
		$s5 = {70 72 69 6E 74 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 68 31 3E 23 77 6F 72 73 74 20 40 64 61 6C 2E 6E 65 74 3C 2F 68 31 3E 3C 2F 63 65 6E 74 65 72 3E 5C 22 3B}
		$s7 = {70 72 69 6E 74 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 68 31 3E 4C 69 6E 75 78 20 53 68 65 6C 6C 73 3C 2F 68 31 3E 3C 2F 63 65 6E 74 65 72 3E 5C 22 3B}
		$s8 = {24 63 75 72 72 65 6E 74 43 4D 44 20 3D 20 5C 22 6C 73 20 2D 6C 61 5C 22 3B}
		$s14 = {70 72 69 6E 74 20 5C 22 3C 74 72 3E 3C 74 64 3E 3C 62 3E 53 79 73 74 65 6D 20 74 79 70 65 3A 3C 2F 62 3E 3C 2F 74 64 3E 3C 74 64 3E 24 55 4E 61 6D 65 3C 2F 74 64 3E 3C 2F 74 72 3E 5C 22 3B}
		$s19 = {24 63 75 72 72 65 6E 74 43 4D 44 20 3D 20 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 5C 5C 5C 5C 22 2C 5C 22 5C 5C 5C 5C 5C 22 2C 24 5F 50 4F 53 54 5B 27 5F 63 6D 64 27 5D 29 3B}

	condition:
		2 of them
}

rule WebShell_php_webshells_pHpINJ
{
	meta:
		description = "PHP Webshells Github Archive - file pHpINJ.php"
		author = "Florian Roth"
		hash = "75116bee1ab122861b155cc1ce45a112c28b9596"

	strings:
		$s3 = {65 63 68 6F 20 27 3C 61 20 68 72 65 66 3D 27 2E 24 65 78 70 75 72 6C 2E 27 3E 20 43 6C 69 63 6B 20 48 65 72 65 20 74 6F 20 45 78 70 6C 6F 69 74 20 3C 2F 61 3E 20 3C 62 72 20 2F 3E 27 3B}
		$s10 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 20 3D 20 5C 22 3C 3F 70 68 70 20 65 63 68 6F 20 5C 22 24 5F 53 45 52 56 45 52 5B 50 48 50 5F 53 45 4C 46 5D 5C 22 20 3B 20 3F 3E 5C 22 20 6D 65 74 68 6F 64 20 3D 20 5C 22 70 6F 73 74 5C 22 3E}
		$s11 = {24 73 71 6C 20 3D 20 5C 22 30 27 20 55 4E 49 4F 4E 20 53 45 4C 45 43 54 20 27 30 27 20 2C 20 27 3C 3F 20 73 79 73 74 65 6D 28 5C 5C 24 5F 47 45 54 5B 63 70 63 5D 29 3B 65 78 69 74 3B 20 3F 3E 27 20 2C 30 20 2C 30 20 2C 30 20 2C 30 20 49 4E}
		$s13 = {46 75 6C 6C 20 73 65 72 76 65 72 20 70 61 74 68 20 74 6F 20 61 20 77 72 69 74 61 62 6C 65 20 66 69 6C 65 20 77 68 69 63 68 20 77 69 6C 6C 20 63 6F 6E 74 61 69 6E 20 74 68 65 20 50 68 70 20 53 68 65 6C 6C 20 3C 62 72 20 2F 3E}
		$s14 = {24 65 78 70 75 72 6C 3D 20 24 75 72 6C 2E 5C 22 3F 69 64 3D 5C 22 2E 24 73 71 6C 20 3B}
		$s15 = {3C 68 65 61 64 65 72 3E 7C 7C 20 20 20 2E 3A 3A 4E 65 77 73 20 50 48 50 20 53 68 65 6C 6C 20 49 6E 6A 65 63 74 69 6F 6E 3A 3A 2E 20 20 20 7C 7C 3C 2F 68 65 61 64 65 72 3E 20 3C 62 72 20 2F 3E 20 3C 62 72 20 2F 3E}
		$s16 = {3C 69 6E 70 75 74 20 74 79 70 65 20 3D 20 5C 22 73 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 20 3D 20 5C 22 43 72 65 61 74 65 20 45 78 70 6C 6F 69 74 5C 22 3E 20 3C 62 72 20 2F 3E 20 3C 62 72 20 2F 3E}

	condition:
		1 of them
}

rule WebShell_php_webshells_NGH
{
	meta:
		description = "PHP Webshells Github Archive - file NGH.php"
		author = "Florian Roth"
		hash = "c05b5deecfc6de972aa4652cb66da89cfb3e1645"

	strings:
		$s0 = {3C 74 69 74 6C 65 3E 57 65 62 63 6F 6D 6D 61 6E 64 65 72 20 61 74 20 3C 3F 3D 24 5F 53 45 52 56 45 52 5B 5C 22 48 54 54 50 5F 48 4F 53 54 5C 22 5D 3F 3E 3C 2F 74 69 74 6C 65 3E}
		$s2 = {2F 2A 20 57 65 62 63 6F 6D 6D 61 6E 64 65 72 20 62 79 20 43 72 34 73 68 5F 61 6B 61 5F 52 4B 4C 20 76 30 2E 33 2E 39 20 4E 47 48 20 65 64 69 74 69 6F 6E 20 3A 70 20 2A 2F}
		$s5 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 3C 3F 3D 24 73 63 72 69 70 74 3F 3E 3F 61 63 74 3D 62 69 6E 64 73 68 65 6C 6C 20 6D 65 74 68 6F 64 3D 50 4F 53 54 3E}
		$s9 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 3C 3F 3D 24 73 63 72 69 70 74 3F 3E 3F 61 63 74 3D 62 61 63 6B 63 6F 6E 6E 65 63 74 20 6D 65 74 68 6F 64 3D 50 4F 53 54 3E}
		$s11 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 3C 3F 3D 24 73 63 72 69 70 74 3F 3E 3F 61 63 74 3D 6D 6B 64 69 72 20 6D 65 74 68 6F 64 3D 50 4F 53 54 3E}
		$s16 = {64 69 65 28 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 23 44 46 30 30 30 30 3E 4C 6F 67 69 6E 20 65 72 72 6F 72 3C 2F 66 6F 6E 74 3E 5C 22 29 3B}
		$s20 = {3C 62 3E 42 69 6E 64 20 2F 62 69 6E 2F 62 61 73 68 20 61 74 20 70 6F 72 74 3A 20 3C 2F 62 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 74 65 78 74 20 6E 61 6D 65 3D 70 6F 72 74 20 73 69 7A 65 3D 38 3E}

	condition:
		2 of them
}

rule WebShell_php_webshells_matamu
{
	meta:
		description = "PHP Webshells Github Archive - file matamu.php"
		author = "Florian Roth"
		hash = "d477aae6bd2f288b578dbf05c1c46b3aaa474733"

	strings:
		$s2 = {24 63 6F 6D 6D 61 6E 64 20 2E 3D 20 27 20 2D 46 27 3B}
		$s3 = {2F 2A 20 57 65 20 74 72 79 20 61 6E 64 20 6D 61 74 63 68 20 61 20 63 64 20 63 6F 6D 6D 61 6E 64 2E 20 2A 2F}
		$s4 = {64 69 72 65 63 74 6F 72 79 2E 2E 2E 20 54 72 75 73 74 20 6D 65 20 2D 20 69 74 20 77 6F 72 6B 73 20 3A 2D 29 20 2A 2F}
		$s5 = {24 63 6F 6D 6D 61 6E 64 20 2E 3D 20 5C 22 20 31 3E 20 24 74 6D 70 66 69 6C 65 20 32 3E 26 31 3B 20 5C 22 20 2E}
		$s10 = {24 6E 65 77 5F 64 69 72 20 3D 20 24 72 65 67 73 5B 31 5D 3B 20 2F 2F 20 27 63 64 20 2F 73 6F 6D 65 74 68 69 6E 67 2F 2E 2E 2E 27}
		$s16 = {2F 2A 20 54 68 65 20 6C 61 73 74 20 2F 20 69 6E 20 77 6F 72 6B 5F 64 69 72 20 77 65 72 65 20 74 68 65 20 66 69 72 73 74 20 63 68 61 72 65 63 74 65 72 2E}

	condition:
		2 of them
}

rule WebShell_ru24_post_sh
{
	meta:
		description = "PHP Webshells Github Archive - file ru24_post_sh.php"
		author = "Florian Roth"
		hash = "d2c18766a1cd4dda928c12ff7b519578ccec0769"

	strings:
		$s1 = {68 74 74 70 3A 2F 2F 77 77 77 2E 72 75 32 34 2D 74 65 61 6D 2E 6E 65 74}
		$s4 = {69 66 20 28 28 21 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 29 20 7C 7C 20 28 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 3D 5C 22 5C 22 29 29 20 7B 20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 5C 22 69 64 3B 70 77 64 3B 75 6E 61 6D 65 20 2D 61}
		$s6 = {52 75 32 34 50 6F 73 74 57 65 62 53 68 65 6C 6C}
		$s7 = {57 72 69 74 65 64 20 62 79 20 44 72 65 41 6D 65 52 7A}
		$s9 = {24 66 75 6E 63 74 69 6F 6E 3D 70 61 73 73 74 68 72 75 3B 20 2F 2F 20 73 79 73 74 65 6D 2C 20 65 78 65 63 2C 20 63 6D 64}

	condition:
		1 of them
}

rule WebShell_hiddens_shell_v1
{
	meta:
		description = "PHP Webshells Github Archive - file hiddens shell v1.php"
		author = "Florian Roth"
		hash = "1674bd40eb98b48427c547bf9143aa7fbe2f4a59"

	strings:
		$s0 = {3C 3F 24 64 3D 27 47 37 6D 48 57 51 39 76 76 58 69 4C 2F 51 58 32 6F 5A 32 56 54 44 70 6F 36 67 33 46 59 41 61 36 58 2B 38 44 4D 49 7A 63 44 30 65 48 5A 61 42 5A 48 37 6A 46 70 5A 7A 55 7A 37 58 4E 65 6E 78 53 59 76 42 50 32 57 79 33 36 55}

	condition:
		all of them
}

rule WebShell_c99_madnet
{
	meta:
		description = "PHP Webshells Github Archive - file c99_madnet.php"
		author = "Florian Roth"
		hash = "17613df393d0a99fd5bea18b2d4707f566cff219"

	strings:
		$s0 = {24 6D 64 35 5F 70 61 73 73 20 3D 20 5C 22 5C 22 3B 20 2F 2F 49 66 20 6E 6F 20 70 61 73 73 20 74 68 65 6E 20 68 61 73 68}
		$s1 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27}
		$s2 = {24 70 61 73 73 20 3D 20 5C 22 70 61 73 73 5C 22 3B 20 20 2F 2F 50 61 73 73}
		$s3 = {24 6C 6F 67 69 6E 20 3D 20 5C 22 75 73 65 72 5C 22 3B 20 2F 2F 4C 6F 67 69 6E}
		$s4 = {20 20 20 20 20 20 20 20 20 20 20 20 20 2F 2F 41 75 74 68 65 6E 74 69 63 61 74 69 6F 6E}

	condition:
		all of them
}

rule WebShell_c99_locus7s
{
	meta:
		description = "PHP Webshells Github Archive - file c99_locus7s.php"
		author = "Florian Roth"
		hash = "d413d4700daed07561c9f95e1468fb80238fbf3c"

	strings:
		$s8 = {24 65 6E 63 6F 64 65 64 20 3D 20 62 61 73 65 36 34 5F 65 6E 63 6F 64 65 28 66 69 6C 65 5F 67 65 74 5F 63 6F 6E 74 65 6E 74 73 28 24 64 2E 24 66 29 29 3B 20}
		$s9 = {24 66 69 6C 65 20 3D 20 24 74 6D 70 64 69 72 2E 5C 22 64 75 6D 70 5F 5C 22 2E 67 65 74 65 6E 76 28 5C 22 53 45 52 56 45 52 5F 4E 41 4D 45 5C 22 29 2E 5C 22 5F 5C 22 2E 24 64 62 2E 5C 22 5F 5C 22 2E 64 61 74 65 28 5C 22 64 2D 6D 2D 59}
		$s10 = {65 6C 73 65 20 7B 24 74 6D 70 20 3D 20 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 5C 22 2E 2F 64 75 6D 70 5F 5C 22 2E 67 65 74 65 6E 76 28 5C 22 53 45 52 56 45 52 5F 4E 41 4D 45 5C 22 29 2E 5C 22 5F 5C 22 2E 24 73 71}
		$s11 = {24 63 39 39 73 68 5F 73 6F 75 72 63 65 73 75 72 6C 20 3D 20 5C 22 68 74 74 70 3A 2F 2F 6C 6F 63 75 73 37 73 2E 63 6F 6D 2F 5C 22 3B 20 2F 2F 53 6F 75 72 63 65 73 2D 73 65 72 76 65 72 20}
		$s19 = {24 6E 69 78 70 77 64 70 65 72 70 61 67 65 20 3D 20 31 30 30 3B 20 2F 2F 20 47 65 74 20 66 69 72 73 74 20 4E 20 6C 69 6E 65 73 20 66 72 6F 6D 20 2F 65 74 63 2F 70 61 73 73 77 64 20}

	condition:
		2 of them
}

rule WebShell_JspWebshell_1_2
{
	meta:
		description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
		author = "Florian Roth"
		hash = "0bed4a1966117dd872ac9e8dceceb54024a030fa"

	strings:
		$s0 = {53 79 73 74 65 6D 2E 6F 75 74 2E 70 72 69 6E 74 6C 6E 28 5C 22 43 72 65 61 74 65 41 6E 64 44 65 6C 65 74 65 46 6F 6C 64 65 72 20 69 73 20 65 72 72 6F 72 3A 5C 22 2B 65 78 29 3B 20}
		$s1 = {53 74 72 69 6E 67 20 70 61 73 73 77 6F 72 64 3D 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 70 61 73 73 77 6F 72 64 5C 22 29 3B}
		$s3 = {3C 25 40 20 70 61 67 65 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 20 63 68 61 72 73 65 74 3D 47 42 4B 5C 22 20 6C 61 6E 67 75 61 67 65 3D 5C 22 6A 61 76 61 5C 22 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E}
		$s7 = {53 74 72 69 6E 67 20 65 64 69 74 66 69 6C 65 3D 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 65 64 69 74 66 69 6C 65 5C 22 29 3B}
		$s8 = {2F 2F 53 74 72 69 6E 67 20 74 65 6D 70 66 69 6C 65 6E 61 6D 65 3D 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 69 6C 65 5C 22 29 3B}
		$s12 = {70 61 73 73 77 6F 72 64 20 3D 20 28 53 74 72 69 6E 67 29 73 65 73 73 69 6F 6E 2E 67 65 74 41 74 74 72 69 62 75 74 65 28 5C 22 70 61 73 73 77 6F 72 64 5C 22 29 3B}

	condition:
		3 of them
}

rule WebShell_safe0ver
{
	meta:
		description = "PHP Webshells Github Archive - file safe0ver.php"
		author = "Florian Roth"
		hash = "366639526d92bd38ff7218b8539ac0f154190eb8"

	strings:
		$s3 = {24 73 63 72 69 70 74 69 64 65 6E 74 20 3D 20 5C 22 24 73 63 72 69 70 74 54 69 74 6C 65 20 42 79 20 45 76 69 6C 63 30 64 65 72 2E 63 6F 6D 5C 22 3B}
		$s4 = {77 68 69 6C 65 20 28 66 69 6C 65 5F 65 78 69 73 74 73 28 5C 22 24 6C 61 73 74 64 69 72 2F 6E 65 77 66 69 6C 65 24 69 2E 74 78 74 5C 22 29 29}
		$s5 = {65 6C 73 65 20 7B 20 2F 2A 20 3C 21 2D 2D 20 54 68 65 6E 20 69 74 20 6D 75 73 74 20 62 65 20 61 20 46 69 6C 65 2E 2E 2E 20 2D 2D 3E 20 2A 2F}
		$s7 = {24 63 6F 6E 74 65 6E 74 73 20 2E 3D 20 68 74 6D 6C 65 6E 74 69 74 69 65 73 28 20 24 6C 69 6E 65 20 29 20 3B}
		$s8 = {3C 62 72 3E 3C 70 3E 3C 62 72 3E 53 61 66 65 20 4D 6F 64 65 20 42 79 50 41 73 73 3C 70 3E 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54 5C 22 3E}
		$s14 = {65 6C 73 65 69 66 20 28 20 24 63 6D 64 3D 3D 5C 22 75 70 6C 6F 61 64 5C 22 20 29 20 7B 20 2F 2A 20 3C 21 2D 2D 20 55 70 6C 6F 61 64 20 46 69 6C 65 20 66 6F 72 6D 20 2D 2D 3E 20 2A 2F 20}
		$s20 = {2F 2A 20 3C 21 2D 2D 20 45 6E 64 20 6F 66 20 41 63 74 69 6F 6E 73 20 2D 2D 3E 20 2A 2F}

	condition:
		3 of them
}

rule WebShell_Uploader
{
	meta:
		description = "PHP Webshells Github Archive - file Uploader.php"
		author = "Florian Roth"
		hash = "e216c5863a23fde8a449c31660fd413d77cce0b7"

	strings:
		$s1 = {6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 75 73 65 72 66 69 6C 65 2C 20 5C 22 65 6E 74 72 69 6B 61 2E 70 68 70 5C 22 29 3B 20}

	condition:
		all of them
}

rule WebShell_php_webshells_kral
{
	meta:
		description = "PHP Webshells Github Archive - file kral.php"
		author = "Florian Roth"
		hash = "4cd1d1a2fd448cecc605970e3a89f3c2e5c80dfc"

	strings:
		$s1 = {24 61 64 72 65 73 3D 67 65 74 68 6F 73 74 62 79 6E 61 6D 65 28 24 69 70 29 3B}
		$s3 = {63 75 72 6C 5F 73 65 74 6F 70 74 28 24 63 68 2C 43 55 52 4C 4F 50 54 5F 50 4F 53 54 46 49 45 4C 44 53 2C 5C 22 64 6F 6D 61 69 6E 3D 5C 22 2E 24 73 69 74 65 29 3B}
		$s4 = {24 65 6B 6C 65 3D 5C 22 2F 69 6E 64 65 78 2E 70 68 70 3F 6F 70 74 69 6F 6E 3D 63 6F 6D 5F 75 73 65 72 26 76 69 65 77 3D 72 65 73 65 74 26 6C 61 79 6F 75 74 3D 63 6F 6E 66 69 72 6D 5C 22 3B}
		$s16 = {65 63 68 6F 20 24 73 6F 6E 2E 27 20 3C 62 72 3E 20 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 67 72 65 65 6E 5C 22 3E 41 63 63 65 73 73 3C 2F 66 6F 6E 74 3E 3C 62 72 3E 27 3B}
		$s17 = {3C 70 3E 6B 6F 64 6C 61 6D 61 20 62 79 20 3C 61 20 68 72 65 66 3D 5C 22 6D 61 69 6C 74 6F 3A 70 72 69 76 38 63 6F 64 65 72 40 67 6D 61 69 6C 2E 63 6F 6D 5C 22 3E 42 4C 61 53 54 45 52 3C 2F 61 3E 3C 62 72 20 2F}
		$s20 = {3C 70 3E 3C 73 74 72 6F 6E 67 3E 53 65 72 76 65 72 20 6C 69 73 74 65 6C 65 79 69 63 69 3C 2F 73 74 72 6F 6E 67 3E 3C 62 72 20 2F 3E}

	condition:
		2 of them
}

rule WebShell_cgitelnet
{
	meta:
		description = "PHP Webshells Github Archive - file cgitelnet.php"
		author = "Florian Roth"
		hash = "72e5f0e4cd438e47b6454de297267770a36cbeb3"

	strings:
		$s9 = {23 20 41 75 74 68 6F 72 20 48 6F 6D 65 70 61 67 65 3A 20 68 74 74 70 3A 2F 2F 77 77 77 2E 72 6F 68 69 74 61 62 2E 63 6F 6D 2F}
		$s10 = {65 6C 73 69 66 28 24 41 63 74 69 6F 6E 20 65 71 20 5C 22 63 6F 6D 6D 61 6E 64 5C 22 29 20 23 20 75 73 65 72 20 77 61 6E 74 73 20 74 6F 20 72 75 6E 20 61 20 63 6F 6D 6D 61 6E 64}
		$s18 = {23 20 69 6E 20 61 20 63 6F 6D 6D 61 6E 64 20 6C 69 6E 65 20 6F 6E 20 57 69 6E 64 6F 77 73 20 4E 54 2E}
		$s20 = {70 72 69 6E 74 20 5C 22 54 72 61 6E 73 66 65 72 65 64 20 24 54 61 72 67 65 74 46 69 6C 65 53 69 7A 65 20 42 79 74 65 73 2E 3C 62 72 3E 5C 22 3B}

	condition:
		2 of them
}

rule WebShell_simple_backdoor
{
	meta:
		description = "PHP Webshells Github Archive - file simple-backdoor.php"
		author = "Florian Roth"
		hash = "edcd5157a68fa00723a506ca86d6cbb8884ef512"

	strings:
		$s0 = {3C 21 2D 2D 20 53 69 6D 70 6C 65 20 50 48 50 20 62 61 63 6B 64 6F 6F 72 20 62 79 20 44 4B 20 28 68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 29 20 2D 2D 3E}
		$s1 = {3C 21 2D 2D 20 20 20 20 68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 20 20 20 32 30 30 36 20 20 20 20 2D 2D 3E}
		$s2 = {55 73 61 67 65 3A 20 68 74 74 70 3A 2F 2F 74 61 72 67 65 74 2E 63 6F 6D 2F 73 69 6D 70 6C 65 2D 62 61 63 6B 64 6F 6F 72 2E 70 68 70 3F 63 6D 64 3D 63 61 74 2B 2F 65 74 63 2F 70 61 73 73 77 64}
		$s3 = {20 20 20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 2F 70 72 65 3E 5C 22 3B}
		$s4 = {20 20 20 20 20 20 20 20 24 63 6D 64 20 3D 20 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 3B}
		$s5 = {20 20 20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 70 72 65 3E 5C 22 3B}
		$s6 = {69 66 28 69 73 73 65 74 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 29 7B}
		$s7 = {20 20 20 20 20 20 20 20 64 69 65 3B}
		$s8 = {20 20 20 20 20 20 20 20 73 79 73 74 65 6D 28 24 63 6D 64 29 3B}

	condition:
		all of them
}

rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_2
{
	meta:
		description = "PHP Webshells Github Archive - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
		author = "Florian Roth"
		hash = "8fdd4e0e87c044177e9e1c97084eb5b18e2f1c25"

	strings:
		$s1 = {3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 22 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 3E 47 65 74 20 2F 65 74 63 2F 70 61 73 73 77 64 3C 2F 6F 70 74 69 6F 6E 3E}
		$s3 = {78 62 35 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D 3C 2F 46 4F 4E 54 3E 3C 2F 43 45 4E 54 45 52 3E 3C 2F 42 3E 5C 22 29 3B}
		$s4 = {24 76 20 3D 20 40 69 6E 69 5F 67 65 74 28 5C 22 6F 70 65 6E 5F 62 61 73 65 64 69 72 5C 22 29 3B}
		$s6 = {62 79 20 50 48 50 20 45 6D 70 65 72 6F 72 3C 78 62 35 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D 3E}

	condition:
		2 of them
}

rule WebShell_NTDaddy_v1_9
{
	meta:
		description = "PHP Webshells Github Archive - file NTDaddy v1.9.php"
		author = "Florian Roth"
		hash = "79519aa407fff72b7510c6a63c877f2e07d7554b"

	strings:
		$s2 = {7C 20 20 20 20 20 2D 6F 62 7A 65 72 76 65 20 3A 20 6D 72 5F 6F 40 69 68 61 74 65 63 6C 6F 77 6E 73 2E 63 6F 6D 20 7C}
		$s6 = {73 7A 54 65 6D 70 46 69 6C 65 20 3D 20 5C 22 43 3A 5C 5C 5C 22 20 26 20 6F 46 69 6C 65 53 79 73 2E 47 65 74 54 65 6D 70 4E 61 6D 65 28 20 29}
		$s13 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 6E 74 64 61 64 64 79 2E 61 73 70 20 6D 65 74 68 6F 64 3D 70 6F 73 74 3E}
		$s17 = {72 65 73 70 6F 6E 73 65 2E 77 72 69 74 65 28 5C 22 3C 45 52 52 4F 52 3A 20 54 48 49 53 20 49 53 20 4E 4F 54 20 41 20 54 45 58 54 20 46 49 4C 45 3E 5C 22 29}

	condition:
		2 of them
}

rule WebShell_lamashell
{
	meta:
		description = "PHP Webshells Github Archive - file lamashell.php"
		author = "Florian Roth"
		hash = "b71181e0d899b2b07bc55aebb27da6706ea1b560"

	strings:
		$s0 = {69 66 28 28 24 5F 50 4F 53 54 5B 27 65 78 65 27 5D 29 20 3D 3D 20 5C 22 45 78 65 63 75 74 65 5C 22 29 20 7B}
		$s8 = {24 63 75 72 63 6D 64 20 3D 20 24 5F 50 4F 53 54 5B 27 6B 69 6E 67 27 5D 3B}
		$s16 = {5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 77 33 2E 6F 72 67 2F 54 52 2F 68 74 6D 6C 34 2F 6C 6F 6F 73 65 2E 64 74 64 5C 22 3E}
		$s18 = {3C 74 69 74 6C 65 3E 6C 61 6D 61 27 73 27 68 65 6C 6C 20 76 2E 20 33 2E 30 3C 2F 74 69 74 6C 65 3E}
		$s19 = {5F 7C 5F 20 20 4F 20 20 20 20 5F 20 20 20 20 4F 20 20 5F 7C 5F}
		$s20 = {24 63 75 72 63 6D 64 20 3D 20 5C 22 6C 73 20 2D 6C 61 68 5C 22 3B}

	condition:
		2 of them
}

rule WebShell_Simple_PHP_backdoor_by_DK
{
	meta:
		description = "PHP Webshells Github Archive - file Simple_PHP_backdoor_by_DK.php"
		author = "Florian Roth"
		hash = "03f6215548ed370bec0332199be7c4f68105274e"
		score = 70

	strings:
		$s0 = {3C 21 2D 2D 20 53 69 6D 70 6C 65 20 50 48 50 20 62 61 63 6B 64 6F 6F 72 20 62 79 20 44 4B 20 28 68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 29 20 2D 2D 3E}
		$s1 = {3C 21 2D 2D 20 20 20 20 68 74 74 70 3A 2F 2F 6D 69 63 68 61 65 6C 64 61 77 2E 6F 72 67 20 20 20 32 30 30 36 20 20 20 20 2D 2D 3E}
		$s2 = {55 73 61 67 65 3A 20 68 74 74 70 3A 2F 2F 74 61 72 67 65 74 2E 63 6F 6D 2F 73 69 6D 70 6C 65 2D 62 61 63 6B 64 6F 6F 72 2E 70 68 70 3F 63 6D 64 3D 63 61 74 2B 2F 65 74 63 2F 70 61 73 73 77 64}
		$s6 = {69 66 28 69 73 73 65 74 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6D 64 27 5D 29 29 7B}
		$s8 = {73 79 73 74 65 6D 28 24 63 6D 64 29 3B}

	condition:
		2 of them
}

rule WebShell_Moroccan_Spamers_Ma_EditioN_By_GhOsT
{
	meta:
		description = "PHP Webshells Github Archive - file Moroccan Spamers Ma-EditioN By GhOsT.php"
		author = "Florian Roth"
		hash = "31e5473920a2cc445d246bc5820037d8fe383201"

	strings:
		$s4 = {24 63 6F 6E 74 65 6E 74 20 3D 20 63 68 75 6E 6B 5F 73 70 6C 69 74 28 62 61 73 65 36 34 5F 65 6E 63 6F 64 65 28 24 63 6F 6E 74 65 6E 74 29 29 3B 20}
		$s12 = {70 72 69 6E 74 20 5C 22 53 65 6E 64 69 6E 67 20 6D 61 69 6C 20 74 6F 20 24 74 6F 2E 2E 2E 2E 2E 2E 2E 20 5C 22 3B 20}
		$s16 = {69 66 20 28 21 24 66 72 6F 6D 20 26 26 20 21 24 73 75 62 6A 65 63 74 20 26 26 20 21 24 6D 65 73 73 61 67 65 20 26 26 20 21 24 65 6D 61 69 6C 6C 69 73 74 29 7B 20}

	condition:
		all of them
}

rule WebShell_C99madShell_v__2_0_madnet_edition
{
	meta:
		description = "PHP Webshells Github Archive - file C99madShell v. 2.0 madnet edition.php"
		author = "Florian Roth"
		hash = "f99f8228eb12746847f54bad45084f19d1a7e111"

	strings:
		$s0 = {24 6D 64 35 5F 70 61 73 73 20 3D 20 5C 22 5C 22 3B 20 2F 2F 49 66 20 6E 6F 20 70 61 73 73 20 74 68 65 6E 20 68 61 73 68}
		$s1 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27}
		$s2 = {24 70 61 73 73 20 3D 20 5C 22 5C 22 3B 20 20 2F 2F 50 61 73 73}
		$s3 = {24 6C 6F 67 69 6E 20 3D 20 5C 22 5C 22 3B 20 2F 2F 4C 6F 67 69 6E}
		$s4 = {2F 2F 41 75 74 68 65 6E 74 69 63 61 74 69 6F 6E}

	condition:
		all of them
}

rule WebShell_CmdAsp_asp_php
{
	meta:
		description = "PHP Webshells Github Archive - file CmdAsp.asp.php.txt"
		author = "Florian Roth"
		hash = "cb18e1ac11e37e236e244b96c2af2d313feda696"

	strings:
		$s1 = {73 7A 54 65 6D 70 46 69 6C 65 20 3D 20 5C 22 43 3A 5C 5C 5C 22 20 26 20 6F 46 69 6C 65 53 79 73 2E 47 65 74 54 65 6D 70 4E 61 6D 65 28 20 29}
		$s4 = {27 20 41 75 74 68 6F 72 3A 20 4D 61 63 65 6F 20 3C 6D 61 63 65 6F 20 40 20 64 6F 67 6D 69 6C 65 2E 63 6F 6D 3E}
		$s5 = {27 20 2D 2D 20 55 73 65 20 61 20 70 6F 6F 72 20 6D 61 6E 27 73 20 70 69 70 65 20 2E 2E 2E 20 61 20 74 65 6D 70 20 66 69 6C 65 20 2D 2D 20 27}
		$s6 = {27 20 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 6F 30 6F 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D}
		$s8 = {27 20 46 69 6C 65 3A 20 43 6D 64 41 73 70 2E 61 73 70}
		$s11 = {3C 2D 2D 20 43 6D 64 41 73 70 2E 61 73 70 20 2D 2D 3E}
		$s14 = {43 61 6C 6C 20 6F 53 63 72 69 70 74 2E 52 75 6E 20 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 65 6D 70 46 69 6C 65 2C 20 30 2C 20 54 72 75 65 29}
		$s16 = {53 65 74 20 6F 53 63 72 69 70 74 4E 65 74 20 3D 20 53 65 72 76 65 72 2E 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 57 53 43 52 49 50 54 2E 4E 45 54 57 4F 52 4B 5C 22 29}
		$s19 = {3C 25 3D 20 5C 22 5C 5C 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 55 73 65 72 4E 61 6D 65 20 25 3E}

	condition:
		4 of them
}

rule WebShell_NCC_Shell
{
	meta:
		description = "PHP Webshells Github Archive - file NCC-Shell.php"
		author = "Florian Roth"
		hash = "64d4495875a809b2730bd93bec2e33902ea80a53"

	strings:
		$s0 = {20 69 66 20 28 69 73 73 65 74 28 24 5F 46 49 4C 45 53 5B 27 70 72 6F 62 65 27 5D 29 20 61 6E 64 20 21 20 24 5F 46 49 4C 45 53 5B 27 70 72 6F 62 65 27 5D 5B 27 65 72 72 6F 72 27 5D 29 20 7B}
		$s1 = {3C 62 3E 2D 2D 43 6F 64 65 64 20 62 79 20 53 69 6C 76 65 72}
		$s2 = {3C 74 69 74 6C 65 3E 55 70 6C 6F 61 64 20 2D 20 53 68 65 6C 6C 2F 44 61 74 65 69 3C 2F 74 69 74 6C 65 3E}
		$s8 = {3C 61 20 68 72 65 66 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 6E 2D 63 2D 63 2E 36 78 2E 74 6F 5C 22 20 74 61 72 67 65 74 3D 5C 22 5F 62 6C 61 6E 6B 5C 22 3E 2D 2D 3E 4E 43 43 3C 2D 2D 3C 2F 61 3E 3C 2F 63 65 6E 74 65 72 3E 3C 2F 62 3E 3C}
		$s14 = {7E 7C 5F 54 65 61 6D 20 2E 3A 4E 61 74 69 6F 6E 61 6C 20 43 72 61 63 6B 65 72 20 43 72 65 77 3A 2E 5F 7C 7E 3C 62 72 3E}
		$s18 = {70 72 69 6E 74 66 28 5C 22 53 69 65 20 69 73 74 20 25 75 20 42 79 74 65 73 20 67 72 6F}

	condition:
		3 of them
}

rule WebShell_php_webshells_README
{
	meta:
		description = "PHP Webshells Github Archive - file README.md"
		author = "Florian Roth"
		hash = "ef2c567b4782c994db48de0168deb29c812f7204"

	strings:
		$s0 = {43 6F 6D 6D 6F 6E 20 70 68 70 20 77 65 62 73 68 65 6C 6C 73 2E 20 44 6F 20 6E 6F 74 20 68 6F 73 74 20 74 68 65 20 66 69 6C 65 28 73 29 20 69 6E 20 79 6F 75 72 20 73 65 72 76 65 72 21}
		$s1 = {70 68 70 2D 77 65 62 73 68 65 6C 6C 73}

	condition:
		all of them
}

rule WebShell_backupsql
{
	meta:
		description = "PHP Webshells Github Archive - file backupsql.php"
		author = "Florian Roth"
		hash = "863e017545ec8e16a0df5f420f2d708631020dd4"

	strings:
		$s0 = {24 68 65 61 64 65 72 73 20 2E 3D 20 5C 22 5C 5C 6E 4D 49 4D 45 2D 56 65 72 73 69 6F 6E 3A 20 31 2E 30 5C 5C 6E 5C 22 20 2E 5C 22 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 6D 75 6C 74 69 70 61 72 74 2F 6D 69 78 65 64 3B 5C 5C 6E 5C 22 20 2E}
		$s1 = {24 66 74 70 63 6F 6E 6E 65 63 74 20 3D 20 5C 22 6E 63 66 74 70 70 75 74 20 2D 75 20 24 66 74 70 5F 75 73 65 72 5F 6E 61 6D 65 20 2D 70 20 24 66 74 70 5F 75 73 65 72 5F 70 61 73 73 20 2D 64 20 64 65 62 73 65 6E 64 65 72 5F 66 74 70 6C 6F 67}
		$s2 = {2A 20 61 73 20 65 6D 61 69 6C 20 61 74 74 61 63 68 6D 65 6E 74 2C 20 6F 72 20 73 65 6E 64 20 74 6F 20 61 20 72 65 6D 6F 74 65 20 66 74 70 20 73 65 72 76 65 72 20 62 79}
		$s16 = {2A 20 4E 65 61 67 75 20 4D 69 68 61 69 3C 6E 65 61 67 75 6D 69 68 61 69 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D 3E}
		$s17 = {24 66 72 6F 6D 20 20 20 20 3D 20 5C 22 4E 65 75 2D 43 6F 6F 6C 40 65 6D 61 69 6C 2E 63 6F 6D 5C 22 3B 20 20 2F 2F 20 57 68 6F 20 73 68 6F 75 6C 64 20 74 68 65 20 65 6D 61 69 6C 73 20 62 65 20 73 65 6E 74 20 66 72 6F 6D 3F 2C 20 6D 61 79 20}

	condition:
		2 of them
}

rule WebShell_AK_74_Security_Team_Web_Shell_Beta_Version
{
	meta:
		description = "PHP Webshells Github Archive - file AK-74 Security Team Web Shell Beta Version.php"
		author = "Florian Roth"
		hash = "c90b0ba575f432ecc08f8f292f3013b5532fe2c4"

	strings:
		$s8 = {2D 20 41 4B 2D 37 34 20 53 65 63 75 72 69 74 79 20 54 65 61 6D 20 57 65 62 20 53 69 74 65 3A 20 77 77 77 2E 61 6B 37 34 2D 74 65 61 6D 2E 6E 65 74}
		$s9 = {3C 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 23 38 33 30 30 30 30 3E 38 2E 20 58 20 46 6F 72 77 61 72 64 65 64 20 46 6F 72 20 49 50 20 2D 20 3C 2F 66 6F 6E 74 3E 3C 2F 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 23 38 33 30 30 30 30 3E 27 2E}
		$s10 = {3C 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 23 38 33 30 30 30 3E 45 78 65 63 75 74 65 20 73 79 73 74 65 6D 20 63 6F 6D 6D 61 6E 64 73 21 3C 2F 66 6F 6E 74 3E 3C 2F 62 3E}

	condition:
		1 of them
}

rule WebShell_php_webshells_cpanel
{
	meta:
		description = "PHP Webshells Github Archive - file cpanel.php"
		author = "Florian Roth"
		hash = "433dab17106b175c7cf73f4f094e835d453c0874"

	strings:
		$s0 = {66 75 6E 63 74 69 6F 6E 20 66 74 70 5F 63 68 65 63 6B 28 24 68 6F 73 74 2C 24 75 73 65 72 2C 24 70 61 73 73 2C 24 74 69 6D 65 6F 75 74 29 7B}
		$s3 = {63 75 72 6C 5F 73 65 74 6F 70 74 28 24 63 68 2C 20 43 55 52 4C 4F 50 54 5F 55 52 4C 2C 20 5C 22 68 74 74 70 3A 2F 2F 24 68 6F 73 74 3A 32 30 38 32 5C 22 29 3B}
		$s4 = {5B 20 75 73 65 72 40 61 6C 74 75 72 6B 73 2E 63 6F 6D 20 5D 23 20 69 6E 66 6F 3C 62 3E 3C 62 72 3E 3C 66 6F 6E 74 20 66 61 63 65 3D 74 61 68 6F 6D 61 3E 3C 62 72 3E}
		$s12 = {63 75 72 6C 5F 73 65 74 6F 70 74 28 24 63 68 2C 20 43 55 52 4C 4F 50 54 5F 46 54 50 4C 49 53 54 4F 4E 4C 59 2C 20 31 29 3B}
		$s13 = {50 6F 77 65 72 66 75 6C 20 74 6F 6F 6C 20 2C 20 66 74 70 20 61 6E 64 20 63 50 61 6E 65 6C 20 62 72 75 74 65 20 66 6F 72 63 65 72 20 2C 20 70 68 70 20 35 2E 32 2E 39 20 73 61 66 65 5F 6D 6F 64 65 20 26 20 6F 70 65 6E 5F 62 61 73 65 64 69 72}
		$s20 = {3C 62 72 3E 3C 62 3E 50 6C 65 61 73 65 20 65 6E 74 65 72 20 79 6F 75 72 20 55 53 45 52 4E 41 4D 45 20 61 6E 64 20 50 41 53 53 57 4F 52 44 20 74 6F 20 6C 6F 67 6F 6E 3C 62 72 3E}

	condition:
		2 of them
}

rule WebShell_accept_language
{
	meta:
		description = "PHP Webshells Github Archive - file accept_language.php"
		author = "Florian Roth"
		hash = "180b13576f8a5407ab3325671b63750adbcb62c9"

	strings:
		$s0 = {3C 3F 70 68 70 20 70 61 73 73 74 68 72 75 28 67 65 74 65 6E 76 28 5C 22 48 54 54 50 5F 41 43 43 45 50 54 5F 4C 41 4E 47 55 41 47 45 5C 22 29 29 3B 20 65 63 68 6F 20 27 3C 62 72 3E 20 62 79 20 71 31 77 32 65 33 72 34 27 3B 20 3F 3E}

	condition:
		all of them
}

rule WebShell_php_webshells_529
{
	meta:
		description = "PHP Webshells Github Archive - file 529.php"
		author = "Florian Roth"
		hash = "ba3fb2995528307487dff7d5b624d9f4c94c75d3"

	strings:
		$s0 = {3C 70 3E 4D 6F 72 65 3A 20 3C 61 20 68 72 65 66 3D 5C 22 2F 5C 22 3E 4D 64 35 43 72 61 63 6B 69 6E 67 2E 43 6F 6D 20 43 72 65 77 3C 2F 61 3E 20}
		$s7 = {68 72 65 66 3D 5C 22 2F 5C 22 20 74 69 74 6C 65 3D 5C 22 53 65 63 75 72 69 74 79 68 6F 75 73 65 5C 22 3E 53 65 63 75 72 69 74 79 20 48 6F 75 73 65 20 2D 20 53 68 65 6C 6C 20 43 65 6E 74 65 72 20 2D 20 45 64 69 74 65 64 20 42 79 20 4B 69 6E}
		$s9 = {65 63 68 6F 20 27 3C 50 52 45 3E 3C 50 3E 54 68 69 73 20 69 73 20 65 78 70 6C 6F 69 74 20 66 72 6F 6D 20 3C 61 20}
		$s10 = {54 68 69 73 20 45 78 70 6C 6F 69 74 20 57 61 73 20 45 64 69 74 65 64 20 42 79 20 4B 69 6E 67 44 65 66 61 63 65 72}
		$s13 = {73 61 66 65 5F 6D 6F 64 65 20 61 6E 64 20 6F 70 65 6E 5F 62 61 73 65 64 69 72 20 42 79 70 61 73 73 20 50 48 50 20 35 2E 32 2E 39 20}
		$s14 = {24 68 61 72 64 73 74 79 6C 65 20 3D 20 65 78 70 6C 6F 64 65 28 5C 22 2F 5C 22 2C 20 24 66 69 6C 65 29 3B 20}
		$s20 = {77 68 69 6C 65 28 24 6C 65 76 65 6C 2D 2D 29 20 63 68 64 69 72 28 5C 22 2E 2E 5C 22 29 3B 20}

	condition:
		2 of them
}

rule WebShell_STNC_WebShell_v0_8
{
	meta:
		description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
		author = "Florian Roth"
		hash = "52068c9dff65f1caae8f4c60d0225708612bb8bc"

	strings:
		$s3 = {69 66 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 5C 22 61 63 74 69 6F 6E 5C 22 5D 29 29 20 24 61 63 74 69 6F 6E 20 3D 20 24 5F 50 4F 53 54 5B 5C 22 61 63 74 69 6F 6E 5C 22 5D 3B}
		$s8 = {65 6C 73 65 69 66 28 66 65 28 5C 22 73 79 73 74 65 6D 5C 22 29 29 7B 6F 62 5F 73 74 61 72 74 28 29 3B 73 79 73 74 65 6D 28 24 73 29 3B 24 72 3D 6F 62 5F 67 65 74 5F 63 6F 6E 74 65 6E 74 73 28 29 3B 6F 62 5F 65 6E 64 5F 63 6C 65 61 6E 28 29}
		$s13 = {7B 20 24 70 77 64 20 3D 20 24 5F 50 4F 53 54 5B 5C 22 70 77 64 5C 22 5D 3B 20 24 74 79 70 65 20 3D 20 66 69 6C 65 74 79 70 65 28 24 70 77 64 29 3B 20 69 66 28 24 74 79 70 65 20 3D 3D 3D 20 5C 22 64 69 72 5C 22 29 63 68 64 69 72 28 24 70 77}

	condition:
		2 of them
}

rule WebShell_php_webshells_tryag
{
	meta:
		description = "PHP Webshells Github Archive - file tryag.php"
		author = "Florian Roth"
		hash = "42d837e9ab764e95ed11b8bd6c29699d13fe4c41"

	strings:
		$s1 = {3C 74 69 74 6C 65 3E 54 72 59 61 47 20 54 65 61 6D 20 2D 20 54 72 59 61 47 2E 70 68 70 20 2D 20 45 64 69 74 65 64 20 42 79 20 4B 69 6E 67 44 65 66 61 63 65 72 3C 2F 74 69 74 6C 65 3E}
		$s3 = {24 74 61 62 6C 65 64 75 6D 70 20 3D 20 5C 22 44 52 4F 50 20 54 41 42 4C 45 20 49 46 20 45 58 49 53 54 53 20 24 74 61 62 6C 65 3B 5C 5C 6E 5C 22 3B 20}
		$s6 = {24 73 74 72 69 6E 67 20 3D 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 73 74 72 69 6E 67 27 5D 29 20 3F 20 24 5F 50 4F 53 54 5B 27 73 74 72 69 6E 67 27 5D 20 3A 20 30 3B 20}
		$s7 = {24 74 61 62 6C 65 64 75 6D 70 20 2E 3D 20 5C 22 43 52 45 41 54 45 20 54 41 42 4C 45 20 24 74 61 62 6C 65 20 28 5C 5C 6E 5C 22 3B 20}
		$s14 = {65 63 68 6F 20 5C 22 3C 63 65 6E 74 65 72 3E 3C 64 69 76 20 69 64 3D 6C 6F 67 6F 73 74 72 69 70 3E 45 64 69 74 20 66 69 6C 65 3A 20 24 65 64 69 74 66 69 6C 65 20 3C 2F 64 69 76 3E 3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 27 24 52 45 51 55 45}

	condition:
		3 of them
}

rule WebShell_dC3_Security_Crew_Shell_PRiV_2
{
	meta:
		description = "PHP Webshells Github Archive - file dC3 Security Crew Shell PRiV.php"
		author = "Florian Roth"
		hash = "9077eb05f4ce19c31c93c2421430dd3068a37f17"

	strings:
		$s0 = {40 72 6D 64 69 72 28 24 5F 47 45 54 5B 27 66 69 6C 65 27 5D 29 20 6F 72 20 64 69 65 20 28 5C 22 5B 2D 5D 45 72 72 6F 72 20 64 65 6C 65 74 69 6E 67 20 64 69 72 21 5C 22 29 3B}
		$s9 = {68 65 61 64 65 72 28 5C 22 4C 61 73 74 2D 4D 6F 64 69 66 69 65 64 3A 20 5C 22 2E 64 61 74 65 28 5C 22 72 5C 22 2C 66 69 6C 65 6D 74 69 6D 65 28 5F 5F 46 49 4C 45 5F 5F 29 29 29 3B}
		$s13 = {68 65 61 64 65 72 28 5C 22 43 6F 6E 74 65 6E 74 2D 74 79 70 65 3A 20 69 6D 61 67 65 2F 67 69 66 5C 22 29 3B}
		$s14 = {40 63 6F 70 79 28 24 66 69 6C 65 2C 24 74 6F 29 20 6F 72 20 64 69 65 20 28 5C 22 5B 2D 5D 45 72 72 6F 72 20 63 6F 70 79 69 6E 67 20 66 69 6C 65 21 5C 22 29 3B}
		$s20 = {69 66 20 28 69 73 73 65 74 28 24 5F 47 45 54 5B 27 72 65 6E 61 6D 65 5F 61 6C 6C 27 5D 29 29 20 7B}

	condition:
		3 of them
}

rule WebShell_qsd_php_backdoor
{
	meta:
		description = "PHP Webshells Github Archive - file qsd-php-backdoor.php"
		author = "Florian Roth"
		hash = "4856bce45fc5b3f938d8125f7cdd35a8bbae380f"

	strings:
		$s1 = {2F 2F 20 41 20 72 6F 62 75 73 74 20 62 61 63 6B 64 6F 6F 72 20 73 63 72 69 70 74 20 6D 61 64 65 20 62 79 20 44 61 6E 69 65 6C 20 42 65 72 6C 69 6E 65 72 20 2D 20 68 74 74 70 3A 2F 2F 77 77 77 2E 71 73 64 63 6F 6E 73 75 6C 74 69 6E 67 2E 63}
		$s2 = {69 66 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 5C 22 6E 65 77 63 6F 6E 74 65 6E 74 5C 22 5D 29 29}
		$s3 = {66 6F 72 65 61 63 68 28 24 70 61 72 74 73 20 61 73 20 24 76 61 6C 29 2F 2F 41 73 73 65 6D 62 6C 65 20 74 68 65 20 70 61 74 68 20 62 61 63 6B 20 74 6F 67 65 74 68 65 72}
		$s7 = {24 5F 50 4F 53 54 5B 5C 22 6E 65 77 63 6F 6E 74 65 6E 74 5C 22 5D 3D 75 72 6C 64 65 63 6F 64 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 24 5F 50 4F 53 54 5B 5C 22 6E 65 77 63 6F 6E 74 65 6E 74 5C 22 5D 29 29 3B}

	condition:
		2 of them
}

rule WebShell_php_webshells_spygrup
{
	meta:
		description = "PHP Webshells Github Archive - file spygrup.php"
		author = "Florian Roth"
		hash = "12f9105332f5dc5d6360a26706cd79afa07fe004"

	strings:
		$s2 = {6B 69 6E 67 64 65 66 61 63 65 72 40 6D 73 6E 2E 63 6F 6D 3C 2F 46 4F 4E 54 3E 3C 2F 43 45 4E 54 45 52 3E 3C 2F 42 3E 5C 22 29 3B}
		$s6 = {69 66 28 24 5F 50 4F 53 54 5B 27 72 6F 6F 74 27 5D 29 20 24 72 6F 6F 74 20 3D 20 24 5F 50 4F 53 54 5B 27 72 6F 6F 74 27 5D 3B}
		$s12 = {5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 66 69 6C 65 29 2E 5C 22 20 42 75 20 44 6F 73 79 61 20 7A 61 74 65 6E 20 47 6F 72 75 6E 74 75 6C 65 6E 69 79 6F 72 3C 6B 69 6E 67 64 65 66 61 63 65 72 40 6D 73 6E 2E 63 6F 6D 3E}
		$s18 = {42 79 20 4B 69 6E 67 44 65 66 61 63 65 72 20 46 72 6F 6D 20 53 70 79 67 72 75 70 2E 6F 72 67 3E}

	condition:
		3 of them
}

rule WebShell_Web_shell__c_ShAnKaR
{
	meta:
		description = "PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php"
		author = "Florian Roth"
		hash = "3dd4f25bd132beb59d2ae0c813373c9ea20e1b7a"

	strings:
		$s0 = {68 65 61 64 65 72 28 5C 22 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 5C 22 2E 66 69 6C 65 73 69 7A 65 28 24 5F 50 4F 53 54 5B 27 64 6F 77 6E 66 27 5D 29 29 3B}
		$s5 = {69 66 28 24 5F 50 4F 53 54 5B 27 73 61 76 65 27 5D 3D 3D 30 29 7B 65 63 68 6F 20 5C 22 3C 74 65 78 74 61 72 65 61 20 63 6F 6C 73 3D 37 30 20 72 6F 77 73 3D 31 30 3E 5C 22 2E 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 24 64 75 6D 70}
		$s6 = {77 72 69 74 65 28 5C 22 23 5C 5C 6E 23 53 65 72 76 65 72 20 3A 20 5C 22 2E 67 65 74 65 6E 76 28 27 53 45 52 56 45 52 5F 4E 41 4D 45 27 29 2E 5C 22}
		$s12 = {66 6F 72 65 61 63 68 28 40 66 69 6C 65 28 24 5F 50 4F 53 54 5B 27 70 61 73 73 77 64 27 5D 29 20 61 73 20 24 66 65 64 29 65 63 68 6F 20 24 66 65 64 3B}

	condition:
		2 of them
}

rule WebShell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz
{
	meta:
		description = "PHP Webshells Github Archive - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.php"
		author = "Florian Roth"
		hash = "5fe8c1d01dc5bc70372a8a04410faf8fcde3cb68"

	strings:
		$s7 = {3C 6D 65 74 61 20 6E 61 6D 65 3D 5C 22 43 6F 70 79 72 69 67 68 74 5C 22 20 63 6F 6E 74 65 6E 74 3D 54 6F 75 43 68 20 42 79 20 69 4A 4F 6F 5C 22 3E}
		$s11 = {64 69 72 65 63 74 6F 72 79 2E 2E 2E 20 54 72 75 73 74 20 6D 65 20 2D 20 69 74 20 77 6F 72 6B 73 20 3A 2D 29 20 2A 2F}
		$s15 = {2F 2A 20 6C 73 20 6C 6F 6F 6B 73 20 6D 75 63 68 20 62 65 74 74 65 72 20 77 69 74 68 20 27 20 2D 46 27 2C 20 49 4D 48 4F 2E 20 2A 2F}
		$s16 = {7D 20 65 6C 73 65 20 69 66 20 28 24 63 6F 6D 6D 61 6E 64 20 3D 3D 20 27 6C 73 27 29 20 7B}

	condition:
		3 of them
}

rule WebShell_Gamma_Web_Shell
{
	meta:
		description = "PHP Webshells Github Archive - file Gamma Web Shell.php"
		author = "Florian Roth"
		hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"

	strings:
		$s4 = {24 6F 6B 5F 63 6F 6D 6D 61 6E 64 73 20 3D 20 5B 27 6C 73 27 2C 20 27 6C 73 20 2D 6C 27 2C 20 27 70 77 64 27 2C 20 27 75 70 74 69 6D 65 27 5D 3B}
		$s8 = {23 23 23 20 47 61 6D 6D 61 20 47 72 6F 75 70 20 3C 68 74 74 70 3A 2F 2F 77 77 77 2E 67 61 6D 6D 61 63 65 6E 74 65 72 2E 63 6F 6D 3E}
		$s15 = {6D 79 20 24 65 72 72 6F 72 20 3D 20 5C 22 54 68 69 73 20 63 6F 6D 6D 61 6E 64 20 69 73 20 6E 6F 74 20 61 76 61 69 6C 61 62 6C 65 20 69 6E 20 74 68 65 20 72 65 73 74 72 69 63 74 65 64 20 6D 6F 64 65 2E 5C 5C 6E 5C 22 3B}
		$s20 = {6D 79 20 24 63 6F 6D 6D 61 6E 64 20 3D 20 24 73 65 6C 66 2D 3E 71 75 65 72 79 28 27 63 6F 6D 6D 61 6E 64 27 29 3B}

	condition:
		2 of them
}

rule WebShell_php_webshells_aspydrv
{
	meta:
		description = "PHP Webshells Github Archive - file aspydrv.php"
		author = "Florian Roth"
		hash = "3d8996b625025dc549d73cdb3e5fa678ab35d32a"

	strings:
		$s0 = {54 61 72 67 65 74 20 3D 20 5C 22 44 3A 5C 5C 68 73 68 6F 6D 65 5C 5C 6D 61 73 74 65 72 68 72 5C 5C 6D 61 73 74 65 72 68 72 2E 63 6F 6D 5C 5C 5C 22 20 20 27 20 2D 2D 2D 44 69 72 65 63 74 6F 72 79 20 74 6F 20 77 68 69 63 68 20 66 69 6C 65 73}
		$s1 = {6E 50 6F 73 20 3D 20 49 6E 73 74 72 42 28 6E 50 6F 73 45 6E 64 2C 20 62 69 44 61 74 61 2C 20 43 42 79 74 65 53 74 72 69 6E 67 28 5C 22 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 5C 22 29 29}
		$s3 = {44 6F 63 75 6D 65 6E 74 2E 66 72 6D 53 51 4C 2E 6D 50 61 67 65 2E 76 61 6C 75 65 20 3D 20 44 6F 63 75 6D 65 6E 74 2E 66 72 6D 53 51 4C 2E 6D 50 61 67 65 2E 76 61 6C 75 65 20 2D 20 31}
		$s17 = {49 66 20 72 65 71 75 65 73 74 2E 71 75 65 72 79 73 74 72 69 6E 67 28 5C 22 67 65 74 44 52 56 73 5C 22 29 3D 5C 22 40 5C 22 20 74 68 65 6E}
		$s20 = {27 20 2D 2D 2D 43 6F 70 79 20 54 6F 6F 20 46 6F 6C 64 65 72 20 72 6F 75 74 69 6E 65 20 53 74 61 72 74}

	condition:
		3 of them
}

rule WebShell_JspWebshell_1_2_2
{
	meta:
		description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
		author = "Florian Roth"
		hash = "184fc72b51d1429c44a4c8de43081e00967cf86b"

	strings:
		$s0 = {53 79 73 74 65 6D 2E 6F 75 74 2E 70 72 69 6E 74 6C 6E 28 5C 22 43 72 65 61 74 65 41 6E 64 44 65 6C 65 74 65 46 6F 6C 64 65 72 20 69 73 20 65 72 72 6F 72 3A 5C 22 2B 65 78 29 3B 20}
		$s3 = {3C 25 40 20 70 61 67 65 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 5C 22 74 65 78 74 2F 68 74 6D 6C 3B 20 63 68 61 72 73 65 74 3D 47 42 4B 5C 22 20 6C 61 6E 67 75 61 67 65 3D 5C 22 6A 61 76 61 5C 22 20 69 6D 70 6F 72 74 3D 5C 22 6A 61 76 61 2E}
		$s4 = {2F 2F 20 53 74 72 69 6E 67 20 74 65 6D 70 66 69 6C 65 70 61 74 68 3D 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 66 69 6C 65 70 61 74 68 5C 22 29 3B}
		$s15 = {65 6E 64 50 6F 69 6E 74 3D 72 61 6E 64 6F 6D 31 2E 67 65 74 46 69 6C 65 50 6F 69 6E 74 65 72 28 29 3B}
		$s20 = {69 66 20 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 28 5C 22 63 6F 6D 6D 61 6E 64 5C 22 29 20 21 3D 20 6E 75 6C 6C 29 20 7B}

	condition:
		3 of them
}

rule WebShell_g00nshell_v1_3
{
	meta:
		description = "PHP Webshells Github Archive - file g00nshell-v1.3.php"
		author = "Florian Roth"
		hash = "70fe072e120249c9e2f0a8e9019f984aea84a504"

	strings:
		$s10 = {23 54 6F 20 65 78 65 63 75 74 65 20 63 6F 6D 6D 61 6E 64 73 2C 20 73 69 6D 70 6C 79 20 69 6E 63 6C 75 64 65 20 3F 63 6D 64 3D 5F 5F 5F 20 69 6E 20 74 68 65 20 75 72 6C 2E 20 23}
		$s15 = {24 71 75 65 72 79 20 3D 20 5C 22 53 48 4F 57 20 43 4F 4C 55 4D 4E 53 20 46 52 4F 4D 20 5C 22 20 2E 20 24 5F 47 45 54 5B 27 74 61 62 6C 65 27 5D 3B}
		$s16 = {24 75 61 6B 65 79 20 3D 20 5C 22 37 32 34 65 61 30 35 35 62 39 37 35 36 32 31 62 39 64 36 37 39 66 37 30 37 37 32 35 37 62 64 39 5C 22 3B 20 2F 2F 20 4D 44 35 20 65 6E 63 6F 64 65 64 20 75 73 65 72 2D 61 67 65 6E 74}
		$s17 = {65 63 68 6F 28 5C 22 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 27 47 45 54 27 20 6E 61 6D 65 3D 27 73 68 65 6C 6C 27 3E 5C 22 29 3B}
		$s18 = {65 63 68 6F 28 5C 22 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 27 70 6F 73 74 27 20 61 63 74 69 6F 6E 3D 27 3F 61 63 74 3D 73 71 6C 27 3E 5C 22 29 3B}

	condition:
		2 of them
}

rule WebShell_WinX_Shell
{
	meta:
		description = "PHP Webshells Github Archive - file WinX Shell.php"
		author = "Florian Roth"
		hash = "a94d65c168344ad9fa406d219bdf60150c02010e"

	strings:
		$s4 = {2F 2F 20 49 74 27 73 20 73 69 6D 70 6C 65 20 73 68 65 6C 6C 20 66 6F 72 20 61 6C 6C 20 57 69 6E 20 4F 53 2E}
		$s5 = {2F 2F 2D 2D 2D 2D 2D 2D 2D 20 5B 6E 65 74 73 74 61 74 20 2D 61 6E 5D 20 61 6E 64 20 5B 69 70 63 6F 6E 66 69 67 5D 20 61 6E 64 20 5B 74 61 73 6B 6C 69 73 74 5D 20 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D}
		$s6 = {3C 68 74 6D 6C 3E 3C 68 65 61 64 3E 3C 74 69 74 6C 65 3E 2D 3A 5B 47 72 65 65 6E 77 6F 6F 44 5D 3A 2D 20 57 69 6E 58 20 53 68 65 6C 6C 3C 2F 74 69 74 6C 65 3E 3C 2F 68 65 61 64 3E}
		$s13 = {2F 2F 20 43 72 65 61 74 65 64 20 62 79 20 67 72 65 65 6E 77 6F 6F 64 20 66 72 6F 6D 20 6E 35 37}
		$s20 = {20 69 66 20 28 69 73 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 75 73 65 72 66 69 6C 65 29 29 20 7B}

	condition:
		3 of them
}

rule WebShell_PHANTASMA
{
	meta:
		description = "PHP Webshells Github Archive - file PHANTASMA.php"
		author = "Florian Roth"
		hash = "cd12d42abf854cd34ff9e93a80d464620af6d75e"

	strings:
		$s12 = {5C 22 20 20 20 20 70 72 69 6E 74 66 28 5C 5C 5C 22 55 73 61 67 65 3A 20 25 73 20 5B 48 6F 73 74 5D 20 3C 70 6F 72 74 3E 5C 5C 5C 5C 6E 5C 5C 5C 22 2C 20 61 72 67 76 5B 30 5D 29 3B 5C 5C 6E 5C 22 20 2E}
		$s15 = {69 66 20 28 24 70 6F 72 74 73 63 61 6E 20 21 3D 20 5C 22 5C 22 29 20 7B}
		$s16 = {65 63 68 6F 20 5C 22 3C 62 72 3E 42 61 6E 6E 65 72 3A 20 24 67 65 74 20 3C 62 72 3E 3C 62 72 3E 5C 22 3B}
		$s20 = {24 64 6F 6E 6F 20 3D 20 67 65 74 5F 63 75 72 72 65 6E 74 5F 75 73 65 72 28 20 29 3B}

	condition:
		3 of them
}

rule WebShell_php_webshells_cw
{
	meta:
		description = "PHP Webshells Github Archive - file cw.php"
		author = "Florian Roth"
		hash = "e65e0670ef6edf0a3581be6fe5ddeeffd22014bf"

	strings:
		$s1 = {2F 2F 20 44 75 6D 70 20 44 61 74 61 62 61 73 65 20 5B 70 61 63 75 63 63 69 2E 63 6F 6D 5D}
		$s2 = {24 64 75 6D 70 20 3D 20 5C 22 2D 2D 20 44 61 74 61 62 61 73 65 3A 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 64 62 27 5D 20 2E 5C 22 20 5C 5C 6E 5C 22 3B}
		$s7 = {24 61 69 64 73 20 3D 20 70 61 73 73 74 68 72 75 28 5C 22 70 65 72 6C 20 63 62 73 2E 70 6C 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 63 6F 6E 6E 68 6F 73 74 27 5D 2E 5C 22 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 63 6F 6E 6E 70 6F 72 74 27 5D 29 3B}
		$s8 = {3C 62 3E 49 50 3A 3C 2F 62 3E 20 3C 75 3E 5C 22 20 2E 20 24 5F 53 45 52 56 45 52 5B 27 52 45 4D 4F 54 45 5F 41 44 44 52 27 5D 20 2E 5C 22 3C 2F 75 3E 20 2D 20 53 65 72 76 65 72 20 49 50 3A 3C 2F 62 3E 20 3C 61 20 68 72 65 66 3D 27 68 74 74}
		$s14 = {24 64 75 6D 70 20 2E 3D 20 5C 22 2D 2D 20 43 79 62 65 72 2D 57 61 72 72 69 6F 72 2E 4F 72 67 5C 5C 6E 5C 22 3B}
		$s20 = {69 66 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 64 6F 65 64 69 74 27 5D 29 20 26 26 20 24 5F 50 4F 53 54 5B 27 65 64 69 74 66 69 6C 65 27 5D 20 21 3D 20 24 64 69 72 29}

	condition:
		3 of them
}

rule WebShell_php_include_w_shell
{
	meta:
		description = "PHP Webshells Github Archive - file php-include-w-shell.php"
		author = "Florian Roth"
		hash = "1a7f4868691410830ad954360950e37c582b0292"

	strings:
		$s13 = {23 20 64 75 6D 70 20 76 61 72 69 61 62 6C 65 73 20 28 44 45 42 55 47 20 53 43 52 49 50 54 29 20 4E 45 45 44 53 20 4D 4F 44 49 46 49 4E 59 20 46 4F 52 20 42 36 34 20 53 54 41 54 55 53 21 21}
		$s17 = {5C 22 70 68 70 73 68 65 6C 6C 61 70 70 5C 22 20 3D 3E 20 5C 22 65 78 70 6F 72 74 20 54 45 52 4D 3D 78 74 65 72 6D 3B 20 62 61 73 68 20 2D 69 5C 22 2C}
		$s19 = {65 6C 73 65 20 69 66 28 24 6E 75 6D 68 6F 73 74 73 20 3D 3D 20 31 29 20 24 73 74 72 4F 75 74 70 75 74 20 2E 3D 20 5C 22 4F 6E 20 31 20 68 6F 73 74 2E 2E 5C 5C 6E 5C 22 3B}

	condition:
		1 of them
}

rule WebShell_mysql_tool
{
	meta:
		description = "PHP Webshells Github Archive - file mysql_tool.php"
		author = "Florian Roth"
		hash = "c9cf8cafcd4e65d1b57fdee5eef98f0f2de74474"

	strings:
		$s12 = {24 64 75 6D 70 20 2E 3D 20 5C 22 2D 2D 20 44 75 6D 70 69 6E 67 20 64 61 74 61 20 66 6F 72 20 74 61 62 6C 65 20 27 24 74 61 62 6C 65 27 5C 5C 6E 5C 22 3B}
		$s20 = {24 64 75 6D 70 20 2E 3D 20 5C 22 43 52 45 41 54 45 20 54 41 42 4C 45 20 24 74 61 62 6C 65 20 28 5C 5C 6E 5C 22 3B}

	condition:
		2 of them
}

rule WebShell_PhpSpy_Ver_2006
{
	meta:
		description = "PHP Webshells Github Archive - file PhpSpy Ver 2006.php"
		author = "Florian Roth"
		hash = "34a89e0ab896c3518d9a474b71ee636ca595625d"

	strings:
		$s2 = {76 61 72 5F 64 75 6D 70 28 40 24 73 68 65 6C 6C 2D 3E 52 65 67 52 65 61 64 28 24 5F 50 4F 53 54 5B 27 72 65 61 64 72 65 67 6E 61 6D 65 27 5D 29 29 3B}
		$s12 = {24 70 72 6F 67 20 3D 20 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 70 72 6F 67 27 5D 29 20 3F 20 24 5F 50 4F 53 54 5B 27 70 72 6F 67 27 5D 20 3A 20 5C 22 2F 63 20 6E 65 74 20 73 74 61 72 74 20 3E 20 5C 22 2E 24 70 61 74 68 6E 61 6D 65 2E}
		$s19 = {24 70 72 6F 67 72 61 6D 20 3D 20 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 70 72 6F 67 72 61 6D 27 5D 29 20 3F 20 24 5F 50 4F 53 54 5B 27 70 72 6F 67 72 61 6D 27 5D 20 3A 20 5C 22 63 3A 5C 5C 77 69 6E 6E 74 5C 5C 73 79 73 74 65 6D 33 32}
		$s20 = {24 72 65 67 76 61 6C 20 3D 20 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 72 65 67 76 61 6C 27 5D 29 20 3F 20 24 5F 50 4F 53 54 5B 27 72 65 67 76 61 6C 27 5D 20 3A 20 27 63 3A 5C 5C 77 69 6E 6E 74 5C 5C 62 61 63 6B 64 6F 6F 72 2E 65 78 65 27}

	condition:
		1 of them
}

rule WebShell_ZyklonShell
{
	meta:
		description = "PHP Webshells Github Archive - file ZyklonShell.php"
		author = "Florian Roth"
		hash = "3fa7e6f3566427196ac47551392e2386a038d61c"

	strings:
		$s0 = {54 68 65 20 72 65 71 75 65 73 74 65 64 20 55 52 4C 20 2F 4E 65 6D 6F 2F 73 68 65 6C 6C 2F 7A 79 6B 6C 6F 6E 73 68 65 6C 6C 2E 74 78 74 20 77 61 73 20 6E 6F 74 20 66 6F 75 6E 64 20 6F 6E 20 74 68 69 73 20 73 65 72 76 65 72 2E 3C 50 3E}
		$s1 = {3C 21 44 4F 43 54 59 50 45 20 48 54 4D 4C 20 50 55 42 4C 49 43 20 5C 22 2D 2F 2F 49 45 54 46 2F 2F 44 54 44 20 48 54 4D 4C 20 32 2E 30 2F 2F 45 4E 5C 22 3E}
		$s2 = {3C 54 49 54 4C 45 3E 34 30 34 20 4E 6F 74 20 46 6F 75 6E 64 3C 2F 54 49 54 4C 45 3E}
		$s3 = {3C 48 31 3E 4E 6F 74 20 46 6F 75 6E 64 3C 2F 48 31 3E}

	condition:
		all of them
}

rule WebShell_php_webshells_myshell
{
	meta:
		description = "PHP Webshells Github Archive - file myshell.php"
		author = "Florian Roth"
		hash = "5bd52749872d1083e7be076a5e65ffcde210e524"

	strings:
		$s0 = {69 66 28 24 6F 6B 3D 3D 66 61 6C 73 65 20 26 26 24 73 74 61 74 75 73 20 26 26 20 24 61 75 74 6F 45 72 72 6F 72 54 72 61 70 29 73 79 73 74 65 6D 28 24 63 6F 6D 6D 61 6E 64 20 2E 20 5C 22 20 31 3E 20 2F 74 6D 70 2F 6F 75 74 70 75}
		$s5 = {73 79 73 74 65 6D 28 24 63 6F 6D 6D 61 6E 64 20 2E 20 5C 22 20 31 3E 20 2F 74 6D 70 2F 6F 75 74 70 75 74 2E 74 78 74 20 32 3E 26 31 3B 20 63 61 74 20 2F 74 6D 70 2F 6F 75 74 70 75 74 2E 74 78 74 3B 20 72 6D 20 2F 74 6D 70 2F 6F}
		$s15 = {3C 74 69 74 6C 65 3E 24 4D 79 53 68 65 6C 6C 56 65 72 73 69 6F 6E 20 2D 20 41 63 63 65 73 73 20 44 65 6E 69 65 64 3C 2F 74 69 74 6C 65 3E}
		$s16 = {7D 24 72 61 34 34 20 20 3D 20 72 61 6E 64 28 31 2C 39 39 39 39 39 29 3B 24 73 6A 39 38 20 3D 20 5C 22 73 68 2D 24 72 61 34 34 5C 22 3B 24 6D 6C 20 3D 20 5C 22 24 73 64 39 38 5C 22 3B 24 61 35 20 3D 20 24 5F 53 45 52 56 45 52 5B 27 48 54 54}

	condition:
		1 of them
}

rule WebShell_php_webshells_lolipop
{
	meta:
		description = "PHP Webshells Github Archive - file lolipop.php"
		author = "Florian Roth"
		hash = "86f23baabb90c93465e6851e40104ded5a5164cb"

	strings:
		$s3 = {24 63 6F 6D 6D 61 6E 64 65 72 20 3D 20 24 5F 50 4F 53 54 5B 27 63 6F 6D 6D 61 6E 64 65 72 27 5D 3B 20}
		$s9 = {24 73 6F 75 72 63 65 67 6F 20 3D 20 24 5F 50 4F 53 54 5B 27 73 6F 75 72 63 65 67 6F 27 5D 3B 20}
		$s20 = {24 72 65 73 75 6C 74 20 3D 20 6D 79 73 71 6C 5F 71 75 65 72 79 28 24 6C 6F 6C 69 31 32 29 20 6F 72 20 64 69 65 20 28 6D 79 73 71 6C 5F 65 72 72 6F 72 28 29 29 3B 20}

	condition:
		all of them
}

rule WebShell_simple_cmd
{
	meta:
		description = "PHP Webshells Github Archive - file simple_cmd.php"
		author = "Florian Roth"
		hash = "466a8caf03cdebe07aa16ad490e54744f82e32c2"

	strings:
		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 54 45 58 54 20 6E 61 6D 65 3D 5C 22 2D 63 6D 64 5C 22 20 73 69 7A 65 3D 36 34 20 76 61 6C 75 65 3D 5C 22 3C 3F 3D 24 63 6D 64 3F 3E 5C 22 20}
		$s2 = {3C 74 69 74 6C 65 3E 47 2D 53 65 63 75 72 69 74 79 20 57 65 62 73 68 65 6C 6C 3C 2F 74 69 74 6C 65 3E}
		$s4 = {3C 3F 20 69 66 28 24 63 6D 64 20 21 3D 20 5C 22 5C 22 29 20 70 72 69 6E 74 20 53 68 65 6C 6C 5F 45 78 65 63 28 24 63 6D 64 29 3B 3F 3E}
		$s6 = {3C 3F 20 24 63 6D 64 20 3D 20 24 5F 52 45 51 55 45 53 54 5B 5C 22 2D 63 6D 64 5C 22 5D 3B 3F 3E}

	condition:
		1 of them
}

rule WebShell_go_shell
{
	meta:
		description = "PHP Webshells Github Archive - file go-shell.php"
		author = "Florian Roth"
		hash = "3dd85981bec33de42c04c53d081c230b5fc0e94f"

	strings:
		$s0 = {23 63 68 61 6E 67 65 20 74 68 69 73 20 70 61 73 73 77 6F 72 64 3B 20 66 6F 72 20 70 6F 77 65 72 20 73 65 63 75 72 69 74 79 20 2D 20 64 65 6C 65 74 65 20 74 68 69 73 20 66 69 6C 65 20 3D 29}
		$s2 = {69 66 20 28 21 64 65 66 69 6E 65 64 24 70 61 72 61 6D 7B 63 6D 64 7D 29 7B 24 70 61 72 61 6D 7B 63 6D 64 7D 3D 5C 22 6C 73 20 2D 6C 61 5C 22 7D 3B}
		$s11 = {6F 70 65 6E 28 46 49 4C 45 48 41 4E 44 4C 45 2C 20 5C 22 63 64 20 24 70 61 72 61 6D 7B 64 69 72 7D 26 26 24 70 61 72 61 6D 7B 63 6D 64 7D 7C 5C 22 29 3B}
		$s12 = {70 72 69 6E 74 20 3C 3C 20 5C 22 5B 6B 61 6C 61 62 61 6E 67 61 5D 5C 22 3B}
		$s13 = {3C 74 69 74 6C 65 3E 47 4F 2E 63 67 69 3C 2F 74 69 74 6C 65 3E}

	condition:
		1 of them
}

rule WebShell_aZRaiLPhp_v1_0
{
	meta:
		description = "PHP Webshells Github Archive - file aZRaiLPhp v1.0.php"
		author = "Florian Roth"
		hash = "a2c609d1a8c8ba3d706d1d70bef69e63f239782b"

	strings:
		$s0 = {3C 66 6F 6E 74 20 73 69 7A 65 3D 27 2B 31 27 63 6F 6C 6F 72 3D 27 23 30 30 30 30 46 46 27 3E 61 5A 52 61 69 4C 50 68 50 27 6E 69 6E 20 55 52 4C 27 73 69 3A 20 68 74 74 70 3A 2F 2F 24 48 54 54 50 5F 48 4F 53 54 24 52 45 44}
		$s4 = {24 66 69 6C 65 70 65 72 6D 3D 62 61 73 65 5F 63 6F 6E 76 65 72 74 28 24 5F 50 4F 53 54 5B 27 66 69 6C 65 70 65 72 6D 27 5D 2C 38 2C 31 30 29 3B}
		$s19 = {74 6F 75 63 68 20 28 5C 22 24 70 61 74 68 2F 24 64 69 73 6D 69 5C 22 29 20 6F 72 20 64 69 65 28 5C 22 44 6F 73 79 61 20 4F 6C 75}
		$s20 = {65 63 68 6F 20 5C 22 3C 64 69 76 20 61 6C 69 67 6E 3D 6C 65 66 74 3E 3C 61 20 68 72 65 66 3D 27 2E 2F 24 74 68 69 73 5F 66 69 6C 65 3F 64 69 72 3D 24 70 61 74 68 2F 24 66 69 6C 65 27 3E 47}

	condition:
		2 of them
}

rule WebShell_webshells_zehir4
{
	meta:
		description = "Webshells Github Archive - file zehir4"
		author = "Florian Roth"
		hash = "788928ae87551f286d189e163e55410acbb90a64"
		score = 55

	strings:
		$s0 = {66 72 61 6D 65 73 2E 62 79 5A 65 68 69 72 2E 64 6F 63 75 6D 65 6E 74 2E 65 78 65 63 43 6F 6D 6D 61 6E 64 28 63 6F 6D 6D 61 6E 64 2C 20 66 61 6C 73 65 2C 20 6F 70 74 69 6F 6E 29 3B}
		$s8 = {72 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 74 69 74 6C 65 3E 5A 65 68 69 72 49 56 20 2D 2D 3E 20 50 6F 77 65 72 65 64 20 42 79 20 5A 65 68 69 72 20 26 6C 74 3B 7A 65 68 69 72 68 61 63 6B 65 72 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D}

	condition:
		1 of them
}

rule WebShell_zehir4_asp_php
{
	meta:
		description = "PHP Webshells Github Archive - file zehir4.asp.php.txt"
		author = "Florian Roth"
		hash = "1d9b78b5b14b821139541cc0deb4cbbd994ce157"

	strings:
		$s4 = {72 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22 3C 74 69 74 6C 65 3E 7A 65 68 69 72 33 20 2D 2D 3E 20 70 6F 77 65 72 65 64 20 62 79 20 7A 65 68 69 72 20 26 6C 74 3B 7A 65 68 69 72 68 61 63 6B 65 72 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D 26}
		$s11 = {66 72 61 6D 65 73 2E 62 79 5A 65 68 69 72 2E 64 6F 63 75 6D 65 6E 74 2E 65 78 65 63 43 6F 6D 6D 61 6E 64 28}
		$s15 = {66 72 61 6D 65 73 2E 62 79 5A 65 68 69 72 2E 64 6F 63 75 6D 65 6E 74 2E 65 78 65 63 43 6F 6D 6D 61 6E 64 28 63 6F}

	condition:
		2 of them
}

rule WebShell_php_webshells_lostDC
{
	meta:
		description = "PHP Webshells Github Archive - file lostDC.php"
		author = "Florian Roth"
		hash = "d54fe07ea53a8929620c50e3a3f8fb69fdeb1cde"

	strings:
		$s0 = {24 69 6E 66 6F 20 2E 3D 20 27 5B 7E 5D 53 65 72 76 65 72 3A 20 27 20 2E 24 5F 53 45 52 56 45 52 5B 27 48 54 54 50 5F 48 4F 53 54 27 5D 20 2E 27 3C 62 72 20 2F 3E 27 3B}
		$s4 = {68 65 61 64 65 72 20 28 20 5C 22 43 6F 6E 74 65 6E 74 2D 44 65 73 63 72 69 70 74 69 6F 6E 3A 20 44 6F 77 6E 6C 6F 61 64 20 6D 61 6E 61 67 65 72 5C 22 20 29 3B}
		$s5 = {70 72 69 6E 74 20 5C 22 3C 63 65 6E 74 65 72 3E 5B 20 47 65 6E 65 72 61 74 69 6F 6E 20 74 69 6D 65 3A 20 5C 22 2E 72 6F 75 6E 64 28 67 65 74 54 69 6D 65 28 29 2D 73 74 61 72 74 54 69 6D 65 2C 34 29 2E 5C 22 20 73 65 63 6F 6E 64}
		$s9 = {69 66 20 28 6D 6B 64 69 72 28 24 5F 50 4F 53 54 5B 27 64 69 72 27 5D 2C 20 30 37 37 37 29 20 3D 3D 20 66 61 6C 73 65 29 20 7B}
		$s12 = {24 72 65 74 20 3D 20 73 68 65 6C 6C 65 78 65 63 28 24 63 6F 6D 6D 61 6E 64 29 3B}

	condition:
		2 of them
}

rule WebShell_CasuS_1_5
{
	meta:
		description = "PHP Webshells Github Archive - file CasuS 1.5.php"
		author = "Florian Roth"
		hash = "7eee8882ad9b940407acc0146db018c302696341"

	strings:
		$s2 = {3C 66 6F 6E 74 20 73 69 7A 65 3D 27 2B 31 27 63 6F 6C 6F 72 3D 27 23 30 30 30 30 46 46 27 3E 3C 75 3E 43 61 73 75 53 20 31 2E 35 27 69 6E 20 55 52 4C 27 73 69 3C 2F 75 3E 3A 20 68 74 74 70 3A 2F 2F 24 48 54 54 50 5F 48 4F}
		$s8 = {24 66 6F 6E 6B 5F 6B 61 70 20 3D 20 67 65 74 5F 63 66 67 5F 76 61 72 28 5C 22 66 6F 6E 6B 73 69 79 6F 6E 6C 61 72 79 5F 6B 61 70 61 74 5C 22 29 3B}
		$s18 = {69 66 20 28 66 69 6C 65 5F 65 78 69 73 74 73 28 5C 22 46 3A 5C 5C 5C 5C 5C 22 29 29 7B}

	condition:
		1 of them
}

rule WebShell_ftpsearch
{
	meta:
		description = "PHP Webshells Github Archive - file ftpsearch.php"
		author = "Florian Roth"
		hash = "c945f597552ccb8c0309ad6d2831c8cabdf4e2d6"

	strings:
		$s0 = {65 63 68 6F 20 5C 22 5B 2D 5D 20 45 72 72 6F 72 20 3A 20 63 6F 75 64 6E 27 74 20 72 65 61 64 20 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 3B}
		$s9 = {40 24 66 74 70 3D 66 74 70 5F 63 6F 6E 6E 65 63 74 28 27 31 32 37 2E 30 2E 30 2E 31 27 29 3B}
		$s12 = {65 63 68 6F 20 5C 22 3C 74 69 74 6C 65 3E 45 64 69 74 65 64 20 42 79 20 4B 69 6E 67 44 65 66 61 63 65 72 3C 2F 74 69 74 6C 65 3E 3C 62 6F 64 79 3E 5C 22 3B}
		$s19 = {65 63 68 6F 20 5C 22 5B 2B 5D 20 46 6F 75 6E 64 65 64 20 5C 22 2E 73 69 7A 65 6F 66 28 24 75 73 65 72 73 29 2E 5C 22 20 65 6E 74 72 79 73 20 69 6E 20 2F 65 74 63 2F 70 61 73 73 77 64 5C 5C 6E 5C 22 3B}

	condition:
		2 of them
}

rule WebShell__Cyber_Shell_cybershell_Cyber_Shell__v_1_0_
{
	meta:
		description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
		hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
		hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"

	strings:
		$s4 = {20 3C 61 20 68 72 65 66 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 63 79 62 65 72 6C 6F 72 64 73 2E 6E 65 74 5C 22 20 74 61 72 67 65 74 3D 5C 22 5F 62 6C 61 6E 6B 5C 22 3E 43 79 62 65 72 20 4C 6F 72 64 73 20 43 6F 6D 6D 75 6E 69 74 79 3C 2F}
		$s10 = {65 63 68 6F 20 5C 22 3C 6D 65 74 61 20 68 74 74 70 2D 65 71 75 69 76 3D 52 65 66 72 65 73 68 20 63 6F 6E 74 65 6E 74 3D 5C 5C 5C 22 30 3B 20 75 72 6C 3D 24 50 48 50 5F 53 45 4C 46 3F 65 64 69 74 3D 24 6E 61 6D 65 6F 66 66 69 6C 65 26 73 68}
		$s11 = {20 2A 20 20 20 43 6F 64 65 64 20 62 79 20 50 69 78 63 68 65 72}
		$s16 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 74 65 78 74 20 73 69 7A 65 3D 35 35 20 6E 61 6D 65 3D 6E 65 77 66 69 6C 65 20 76 61 6C 75 65 3D 5C 22 24 64 2F 6E 65 77 66 69 6C 65 2E 70 68 70 5C 22 3E}

	condition:
		2 of them
}

rule WebShell__Ajax_PHP_Command_Shell_Ajax_PHP_Command_Shell_soldierofallah
{
	meta:
		description = "PHP Webshells Github Archive - from files Ajax_PHP Command Shell.php, Ajax_PHP_Command_Shell.php, soldierofallah.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "fa11deaee821ca3de7ad1caafa2a585ee1bc8d82"
		hash1 = "c0a4ba3e834fb63e0a220a43caaf55c654f97429"
		hash2 = "16fa789b20409c1f2ffec74484a30d0491904064"

	strings:
		$s1 = {27 52 65 61 64 20 2F 65 74 63 2F 70 61 73 73 77 64 27 20 3D 3E 20 5C 22 72 75 6E 63 6F 6D 6D 61 6E 64 28 27 65 74 63 70 61 73 73 77 64 66 69 6C 65 27 2C 27 47 45 54 27 29 5C 22 2C}
		$s2 = {27 52 75 6E 6E 69 6E 67 20 70 72 6F 63 65 73 73 65 73 27 20 3D 3E 20 5C 22 72 75 6E 63 6F 6D 6D 61 6E 64 28 27 70 73 20 2D 61 75 78 27 2C 27 47 45 54 27 29 5C 22 2C}
		$s3 = {24 64 74 20 3D 20 24 5F 50 4F 53 54 5B 27 66 69 6C 65 63 6F 6E 74 65 6E 74 27 5D 3B}
		$s4 = {27 4F 70 65 6E 20 70 6F 72 74 73 27 20 3D 3E 20 5C 22 72 75 6E 63 6F 6D 6D 61 6E 64 28 27 6E 65 74 73 74 61 74 20 2D 61 6E 20 7C 20 67 72 65 70 20 2D 69 20 6C 69 73 74 65 6E 27 2C 27 47 45 54 27 29 5C 22 2C}
		$s6 = {70 72 69 6E 74 20 5C 22 53 6F 72 72 79 2C 20 6E 6F 6E 65 20 6F 66 20 74 68 65 20 63 6F 6D 6D 61 6E 64 20 66 75 6E 63 74 69 6F 6E 73 20 77 6F 72 6B 73 2E 5C 22 3B}
		$s11 = {64 6F 63 75 6D 65 6E 74 2E 63 6D 64 66 6F 72 6D 2E 63 6F 6D 6D 61 6E 64 2E 76 61 6C 75 65 3D 27 27 3B}
		$s12 = {65 6C 73 65 69 66 28 69 73 73 65 74 28 24 5F 47 45 54 5B 27 73 61 76 65 66 69 6C 65 27 5D 29 20 26 26 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 66 69 6C 65 74 6F 73 61 76 65 27 5D 29 20 26 26 20 21 65 6D 70 74 79 28 24 5F 50 4F 53 54}

	condition:
		3 of them
}

rule WebShell_Generic_PHP_7
{
	meta:
		description = "PHP Webshells Github Archive - from files Mysql interface v1.0.php, MySQL Web Interface Version 0.8.php, Mysql_interface_v1.0.php, MySQL_Web_Interface_Version_0.8.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "de98f890790756f226f597489844eb3e53a867a9"
		hash1 = "128988c8ef5294d51c908690d27f69dffad4e42e"
		hash2 = "fd64f2bf77df8bcf4d161ec125fa5c3695fe1267"
		hash3 = "715f17e286416724e90113feab914c707a26d456"

	strings:
		$s0 = {68 65 61 64 65 72 28 5C 22 43 6F 6E 74 65 6E 74 2D 64 69 73 70 6F 73 69 74 69 6F 6E 3A 20 66 69 6C 65 6E 61 6D 65 3D 24 66 69 6C 65 6E 61 6D 65 2E 73 71 6C 5C 22 29 3B}
		$s1 = {65 6C 73 65 20 69 66 28 20 24 61 63 74 69 6F 6E 20 3D 3D 20 5C 22 64 75 6D 70 54 61 62 6C 65 5C 22 20 7C 7C 20 24 61 63 74 69 6F 6E 20 3D 3D 20 5C 22 64 75 6D 70 44 42 5C 22 20 29 20 7B}
		$s2 = {65 63 68 6F 20 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 62 6C 75 65 3E 5B 24 55 53 45 52 4E 41 4D 45 5D 3C 2F 66 6F 6E 74 3E 20 2D 20 5C 5C 6E 5C 22 3B}
		$s4 = {69 66 28 20 24 61 63 74 69 6F 6E 20 3D 3D 20 5C 22 64 75 6D 70 54 61 62 6C 65 5C 22 20 29}

	condition:
		2 of them
}

rule WebShell__Small_Web_Shell_by_ZaCo_small_zaco_zacosmall
{
	meta:
		description = "PHP Webshells Github Archive - from files Small Web Shell by ZaCo.php, small.php, zaco.php, zacosmall.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "b148ead15d34a55771894424ace2a92983351dda"
		hash1 = "e4ba288f6d46dc77b403adf7d411a280601c635b"
		hash2 = "e5713d6d231c844011e9a74175a77e8eb835c856"
		hash3 = "1b836517164c18caf2c92ee2a06c645e26936a0c"

	strings:
		$s2 = {69 66 28 21 24 72 65 73 75 6C 74 32 29 24 64 75 6D 70 5F 66 69 6C 65 2E 3D 27 23 65 72 72 6F 72 20 74 61 62 6C 65 20 27 2E 24 72 6F 77 73 5B 30 5D 3B}
		$s4 = {69 66 28 21 28 40 6D 79 73 71 6C 5F 73 65 6C 65 63 74 5F 64 62 28 24 64 62 5F 64 75 6D 70 2C 24 6D 79 73 71 6C 5F 6C 69 6E 6B 29 29 29 65 63 68 6F 28 27 44 42 20 65 72 72 6F 72 27 29 3B}
		$s6 = {68 65 61 64 65 72 28 27 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 27 2E 73 74 72 6C 65 6E 28 24 64 75 6D 70 5F 66 69 6C 65 29 2E 5C 22 5C 5C 6E 5C 22 29 3B}
		$s20 = {65 63 68 6F 28 27 44 75 6D 70 20 66 6F 72 20 27 2E 24 64 62 5F 64 75 6D 70 2E 27 20 6E 6F 77 20 69 6E 20 27 2E 24 74 6F 5F 66 69 6C 65 29 3B}

	condition:
		2 of them
}

rule WebShell_Generic_PHP_8
{
	meta:
		description = "PHP Webshells Github Archive - from files Macker's Private PHPShell.php, PHP Shell.php, Safe0ver Shell -Safe Mod Bypass By Evilc0der.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "fc1ae242b926d70e32cdb08bbe92628bc5bd7f99"
		hash1 = "9ad55629c4576e5a31dd845012d13a08f1c1f14e"
		hash2 = "c4aa2cf665c784553740c3702c3bfcb5d7af65a3"

	strings:
		$s1 = {65 6C 73 65 69 66 20 28 20 24 63 6D 64 3D 3D 5C 22 66 69 6C 65 5C 22 20 29 20 7B 20 2F 2A 20 3C 21 2D 2D 20 56 69 65 77 20 61 20 66 69 6C 65 20 69 6E 20 74 65 78 74 20 2D 2D 3E 20 2A 2F}
		$s2 = {65 6C 73 65 69 66 20 28 20 24 63 6D 64 3D 3D 5C 22 75 70 6C 6F 61 64 5C 22 20 29 20 7B 20 2F 2A 20 3C 21 2D 2D 20 55 70 6C 6F 61 64 20 46 69 6C 65 20 66 6F 72 6D 20 2D 2D 3E 20 2A 2F 20}
		$s3 = {2F 2A 20 49 20 61 64 64 65 64 20 74 68 69 73 20 74 6F 20 65 6E 73 75 72 65 20 74 68 65 20 73 63 72 69 70 74 20 77 69 6C 6C 20 72 75 6E 20 63 6F 72 72 65 63 74 6C 79 2E 2E 2E}
		$s14 = {3C 21 2D 2D 20 20 20 20 3C 2F 66 6F 72 6D 3E 20 20 20 2D 2D 3E}
		$s15 = {3C 66 6F 72 6D 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 24 53 46 69 6C 65 4E 61 6D 65 3F 24 75 72 6C 41 64 64 5C 5C 5C 22 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50 4F 53 54 5C 5C 5C 22 3E}
		$s20 = {65 6C 73 65 69 66 20 28 20 24 63 6D 64 3D 3D 5C 22 64 6F 77 6E 6C 5C 22 20 29 20 7B 20 2F 2A 3C 21 2D 2D 20 53 61 76 65 20 74 68 65 20 65 64 69 74 65 64 20 66 69 6C 65 20 62 61 63 6B 20 74 6F 20 61 20 66 69 6C 65 20 2D 2D 3E 20 2A 2F}

	condition:
		3 of them
}

rule WebShell__PH_Vayv_PHVayv_PH_Vayv_klasvayv_asp_php
{
	meta:
		description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php, klasvayv.asp.php.txt"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
		hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
		hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
		hash3 = "4f83bc2836601225a115b5ad54496428a507a361"

	strings:
		$s1 = {3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 30 30 30 30 30 30 5C 22 3E 53 69 6C 3C 2F 66 6F 6E 74 3E 3C 2F 61 3E 3C 2F 66 6F 6E 74 3E 3C 2F 74 64 3E}
		$s5 = {3C 74 64 20 77 69 64 74 68 3D 5C 22 31 32 32 5C 22 20 68 65 69 67 68 74 3D 5C 22 31 37 5C 22 20 62 67 63 6F 6C 6F 72 3D 5C 22 23 39 46 39 46 39 46 5C 22 3E}
		$s6 = {6F 6E 66 6F 63 75 73 3D 5C 22 69 66 20 28 74 68 69 73 2E 76 61 6C 75 65 20 3D 3D 20 27 4B 75 6C 6C 61 6E}
		$s16 = {3C 69 6D 67 20 62 6F 72 64 65 72 3D 5C 22 30 5C 22 20 73 72 63 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 61 76 65 6E 74 67 72 75 70 2E 6E 65 74 2F 61 72 73 69 76 2F 6B 6C 61 73 76 61 79 76 2F 31 2E 30 2F 32 2E 67 69 66 5C 22 3E}

	condition:
		2 of them
}

rule WebShell_Generic_PHP_9
{
	meta:
		description = "PHP Webshells Github Archive - from files KAdot Universal Shell v0.1.6.php, KAdot_Universal_Shell_v0.1.6.php, KA_uShell 0.1.6.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "89f2a7007a2cd411e0a7abd2ff5218d212b84d18"
		hash1 = "2266178ad4eb72c2386c0a4d536e5d82bb7ed6a2"
		hash2 = "0daed818cac548324ad0c5905476deef9523ad73"

	strings:
		$s2 = {3A 3C 62 3E 5C 22 20 2E 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 24 5F 50 4F 53 54 5B 27 74 6F 74 27 5D 29 2E 20 5C 22 3C 2F 62 3E 5C 22 3B}
		$s6 = {69 66 20 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 77 71 27 5D 29 20 26 26 20 24 5F 50 4F 53 54 5B 27 77 71 27 5D 3C 3E 5C 22 5C 22 29 20 7B}
		$s12 = {69 66 20 28 21 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 63 27 5D 29 29 7B}
		$s13 = {70 61 73 73 74 68 72 75 28 24 5F 50 4F 53 54 5B 27 63 27 5D 29 3B}
		$s16 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 72 61 64 69 6F 5C 22 20 6E 61 6D 65 3D 5C 22 74 61 63 5C 22 20 76 61 6C 75 65 3D 5C 22 31 5C 22 3E 42 36 34 20 44 65 63 6F 64 65 3C 62 72 3E}
		$s20 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 72 61 64 69 6F 5C 22 20 6E 61 6D 65 3D 5C 22 74 61 63 5C 22 20 76 61 6C 75 65 3D 5C 22 33 5C 22 3E 6D 64 35 20 48 61 73 68}

	condition:
		3 of them
}

rule WebShell__PH_Vayv_PHVayv_PH_Vayv
{
	meta:
		description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
		hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
		hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"

	strings:
		$s4 = {3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54 5C 22 20 61 63 74 69 6F 6E 3D 5C 22 3C 3F 65 63 68 6F 20 5C 22 50 48 56 61 79 76 2E 70 68 70 3F 64 75 7A 6B 61 79 64 65 74 3D 24 64 69 7A 69 6E 2F 24 64 75 7A 65 6E 6C 65}
		$s12 = {3C 3F 20 69 66 20 28 24 65 6B 69 6E 63 69 3D 3D 5C 22 2E 5C 22 20 6F 72 20 20 24 65 6B 69 6E 63 69 3D 3D 5C 22 2E 2E 5C 22 29 20 7B}
		$s17 = {6E 61 6D 65 3D 5C 22 64 75 7A 65 6E 78 32 5C 22 20 76 61 6C 75 65 3D 5C 22 4B 6C 61 73}

	condition:
		2 of them
}

rule WebShell_Generic_PHP_1
{
	meta:
		description = "PHP Webshells Github Archive - from files Dive Shell 1.0 - Emperor Hacking Team.php, Dive_Shell_1.0_Emperor_Hacking_Team.php, SimShell 1.0 - Simorgh Security MGZ.php, SimShell_1.0_-_Simorgh_Security_MGZ.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "3b086b9b53cf9d25ff0d30b1d41bb2f45c7cda2b"
		hash1 = "2558e728184b8efcdb57cfab918d95b06d45de04"
		hash2 = "203a8021192531d454efbc98a3bbb8cabe09c85c"
		hash3 = "b79709eb7801a28d02919c41cc75ac695884db27"

	strings:
		$s1 = {24 74 6F 6B 65 6E 20 3D 20 73 75 62 73 74 72 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 2C 20 30 2C 20 24 6C 65 6E 67 74 68 29 3B}
		$s4 = {76 61 72 20 63 6F 6D 6D 61 6E 64 5F 68 69 73 74 20 3D 20 6E 65 77 20 41 72 72 61 79 28 3C 3F 70 68 70 20 65 63 68 6F 20 24 6A 73 5F 63 6F 6D 6D 61 6E 64 5F 68 69 73 74 20 3F 3E 29 3B}
		$s7 = {24 5F 53 45 53 53 49 4F 4E 5B 27 6F 75 74 70 75 74 27 5D 20 2E 3D 20 68 74 6D 6C 73 70 65 63 69 61 6C 63 68 61 72 73 28 66 67 65 74 73 28 24 69 6F 5B 31 5D 29 2C}
		$s9 = {64 6F 63 75 6D 65 6E 74 2E 73 68 65 6C 6C 2E 63 6F 6D 6D 61 6E 64 2E 76 61 6C 75 65 20 3D 20 63 6F 6D 6D 61 6E 64 5F 68 69 73 74 5B 63 75 72 72 65 6E 74 5F 6C 69 6E 65 5D 3B}
		$s16 = {24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 20 3D 20 24 61 6C 69 61 73 65 73 5B 24 74 6F 6B 65 6E 5D 20 2E 20 73 75 62 73 74 72 28 24 5F 52 45 51 55 45 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 2C 20 24}
		$s19 = {69 66 20 28 65 6D 70 74 79 28 24 5F 53 45 53 53 49 4F 4E 5B 27 63 77 64 27 5D 29 20 7C 7C 20 21 65 6D 70 74 79 28 24 5F 52 45 51 55 45 53 54 5B 27 72 65 73 65 74 27 5D 29 29 20 7B}
		$s20 = {69 66 20 28 65 2E 6B 65 79 43 6F 64 65 20 3D 3D 20 33 38 20 26 26 20 63 75 72 72 65 6E 74 5F 6C 69 6E 65 20 3C 20 63 6F 6D 6D 61 6E 64 5F 68 69 73 74 2E 6C 65 6E 67 74 68 2D 31 29 20 7B}

	condition:
		5 of them
}

rule WebShell_Generic_PHP_2
{
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash2 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash3 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

	strings:
		$s3 = {69 66 28 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 66 69 6C 65 74 6F 27 5D 29 29 7C 7C 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 66 69 6C 65 66 72 6F 6D 27 5D 29 29 29}
		$s4 = {5C 5C 24 70 6F 72 74 20 3D 20 7B 24 5F 50 4F 53 54 5B 27 70 6F 72 74 27 5D 7D 3B}
		$s5 = {24 5F 50 4F 53 54 5B 27 69 6E 73 74 61 6C 6C 70 61 74 68 27 5D 20 3D 20 5C 22 74 65 6D 70 2E 70 6C 5C 22 3B 7D}
		$s14 = {69 66 28 69 73 73 65 74 28 24 5F 50 4F 53 54 5B 27 70 6F 73 74 27 5D 29 20 61 6E 64 20 24 5F 50 4F 53 54 5B 27 70 6F 73 74 27 5D 20 3D 3D 20 5C 22 79 65 73 5C 22 20 61 6E 64 20 40 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 5C 22 75}
		$s16 = {63 6F 70 79 28 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 5C 22 75 73 65 72 66 69 6C 65 5C 22 5D 5B 5C 22 74 6D 70 5F 6E 61 6D 65 5C 22 5D 2C 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 5C 22 75 73 65 72 66 69 6C 65 5C 22 5D}

	condition:
		4 of them
}

rule WebShell__CrystalShell_v_1_erne_stres
{
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, erne.php, stres.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "6eb4ab630bd25bec577b39fb8a657350bf425687"
		hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

	strings:
		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 27 73 75 62 6D 69 74 27 20 76 61 6C 75 65 3D 27 20 20 6F 70 65 6E 20 28 73 68 69 6C 6C 2E 74 78 74 29 20 27 3E}
		$s4 = {76 61 72 5F 64 75 6D 70 28 63 75 72 6C 5F 65 78 65 63 28 24 63 68 29 29 3B}
		$s7 = {69 66 28 65 6D 70 74 79 28 24 5F 50 4F 53 54 5B 27 4D 6F 68 61 6A 65 72 32 32 27 5D 29 29 7B}
		$s10 = {24 6D 3D 24 5F 50 4F 53 54 5B 27 63 75 72 6C 27 5D 3B}
		$s13 = {24 75 31 70 3D 24 5F 50 4F 53 54 5B 27 63 6F 70 79 27 5D 3B}
		$s14 = {69 66 28 65 6D 70 74 79 28 5C 5C 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 29 29 7B}
		$s15 = {24 73 74 72 69 6E 67 20 3D 20 65 78 70 6C 6F 64 65 28 5C 22 7C 5C 22 2C 24 73 74 72 69 6E 67 29 3B}
		$s16 = {24 73 74 72 65 61 6D 20 3D 20 69 6D 61 70 5F 6F 70 65 6E 28 5C 22 2F 65 74 63 2F 70 61 73 73 77 64 5C 22 2C 20 5C 22 5C 22 2C 20 5C 22 5C 22 29 3B}

	condition:
		5 of them
}

rule WebShell_Generic_PHP_3
{
	meta:
		description = "PHP Webshells Github Archive - from files Antichat Shell v1.3.php, Antichat Shell. Modified by Go0o$E.php, Antichat Shell.php, fatal.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "d829e87b3ce34460088c7775a60bded64e530cd4"
		hash1 = "d710c95d9f18ec7c76d9349a28dd59c3605c02be"
		hash2 = "f044d44e559af22a1a7f9db72de1206f392b8976"
		hash3 = "41780a3e8c0dc3cbcaa7b4d3c066ae09fb74a289"

	strings:
		$s0 = {68 65 61 64 65 72 28 27 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 27 2E 66 69 6C 65 73 69 7A 65 28 24 66 69 6C 65 29 2E 27 27 29 3B}
		$s4 = {3C 74 65 78 74 61 72 65 61 20 6E 61 6D 65 3D 5C 5C 5C 22 63 6F 6D 6D 61 6E 64 5C 5C 5C 22 20 72 6F 77 73 3D 5C 5C 5C 22 35 5C 5C 5C 22 20 63 6F 6C 73 3D 5C 5C 5C 22 31 35 30 5C 5C 5C 22 3E 5C 22 2E 40 24 5F 50 4F 53 54 5B 27 63 6F 6D 6D 61}
		$s7 = {69 66 28 66 69 6C 65 74 79 70 65 28 24 64 69 72 20 2E 20 24 66 69 6C 65 29 3D 3D 5C 22 66 69 6C 65 5C 22 29 24 66 69 6C 65 73 5B 5D 3D 24 66 69 6C 65 3B}
		$s14 = {65 6C 73 65 69 66 20 28 28 24 70 65 72 6D 73 20 26 20 30 78 36 30 30 30 29 20 3D 3D 20 30 78 36 30 30 30 29 20 7B 24 69 6E 66 6F 20 3D 20 27 62 27 3B 7D 20}
		$s20 = {24 69 6E 66 6F 20 2E 3D 20 28 28 24 70 65 72 6D 73 20 26 20 30 78 30 30 30 34 29 20 3F 20 27 72 27 20 3A 20 27 2D 27 29 3B}

	condition:
		all of them
}

rule WebShell_Generic_PHP_4
{
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, nshell.php, Loaderz WEB Shell.php, stres.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash2 = "86bc40772de71b1e7234d23cab355e1ff80c474d"
		hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

	strings:
		$s0 = {69 66 20 28 24 66 69 6C 65 6E 61 6D 65 20 21 3D 20 5C 22 2E 5C 22 20 61 6E 64 20 24 66 69 6C 65 6E 61 6D 65 20 21 3D 20 5C 22 2E 2E 5C 22 29 7B}
		$s2 = {24 6F 77 6E 65 72 5B 5C 22 77 72 69 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 32 30 30 29 20 3F 20 27 77 27 20 3A 20 27 2D 27 3B}
		$s5 = {24 6F 77 6E 65 72 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 31 30 30 29 20 3F 20 27 78 27 20 3A 20 27 2D 27 3B}
		$s6 = {24 77 6F 72 6C 64 5B 5C 22 77 72 69 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 30 30 32 29 20 3F 20 27 77 27 20 3A 20 27 2D 27 3B}
		$s7 = {24 77 6F 72 6C 64 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 30 30 31 29 20 3F 20 27 78 27 20 3A 20 27 2D 27 3B}
		$s10 = {66 6F 72 65 61 63 68 20 28 24 61 72 72 20 61 73 20 24 66 69 6C 65 6E 61 6D 65 29 20 7B}
		$s19 = {65 6C 73 65 20 69 66 28 20 24 6D 6F 64 65 20 26 20 30 78 36 30 30 30 20 29 20 7B 20 24 74 79 70 65 3D 27 62 27 3B 20 7D}

	condition:
		all of them
}

rule WebShell_GFS
{
	meta:
		description = "PHP Webshells Github Archive - from files GFS web-shell ver 3.1.7 - PRiV8.php, Predator.php, GFS_web-shell_ver_3.1.7_-_PRiV8.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "c2f1ef6b11aaec255d4dd31efad18a3869a2a42c"
		hash1 = "34f6640985b07009dbd06cd70983451aa4fe9822"
		hash2 = "d25ef72bdae3b3cb0fc0fdd81cfa58b215812a50"

	strings:
		$s0 = {4F 4B 54 73 4E 43 6D 4E 73 62 33 4E 6C 4B 46 4E 55 52 45 39 56 56 43 6B 37 44 51 70 6A 62 47 39 7A 5A 53 68 54 56 45 52 46 55 6C 49 70 4F 77 3D 3D 5C 22 3B}
		$s1 = {6C 49 45 4E 50 54 6B 34 37 44 51 70 6C 65 47 6C 30 49 44 41 37 44 51 70 39 44 51 70 39 5C 22 3B}
		$s2 = {4F 77 30 4B 49 47 52 31 63 44 49 6F 5A 6D 51 73 49 44 49 70 4F 77 30 4B 49 47 56 34 5A 57 4E 73 4B 43 49 76 59 6D 6C 75 4C 33 4E 6F 49 69 77 69 63 32 67 67 4C 57 6B 69 4C 43 42 4F 56 55 78 4D 4B 54 73 4E 43 69 42 6A 62 47 39 7A 5A 53 68 6D}

	condition:
		all of them
}

rule WebShell__CrystalShell_v_1_sosyete_stres
{
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, sosyete.php, stres.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "e32405e776e87e45735c187c577d3a4f98a64059"
		hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

	strings:
		$s1 = {41 3A 76 69 73 69 74 65 64 20 7B 20 43 4F 4C 4F 52 3A 62 6C 75 65 3B 20 54 45 58 54 2D 44 45 43 4F 52 41 54 49 4F 4E 3A 20 6E 6F 6E 65 7D}
		$s4 = {41 3A 61 63 74 69 76 65 20 7B 43 4F 4C 4F 52 3A 62 6C 75 65 3B 20 54 45 58 54 2D 44 45 43 4F 52 41 54 49 4F 4E 3A 20 6E 6F 6E 65 7D}
		$s11 = {73 63 72 6F 6C 6C 62 61 72 2D 64 61 72 6B 73 68 61 64 6F 77 2D 63 6F 6C 6F 72 3A 20 23 31 30 31 38 34 32 3B}
		$s15 = {3C 61 20 62 6F 6F 6B 6D 61 72 6B 3D 5C 22 6D 69 6E 69 70 61 6E 65 6C 5C 22 3E}
		$s16 = {62 61 63 6B 67 72 6F 75 6E 64 2D 63 6F 6C 6F 72 3A 20 23 45 42 45 41 45 41 3B}
		$s18 = {63 6F 6C 6F 72 3A 20 23 44 35 45 43 46 39 3B}
		$s19 = {3C 63 65 6E 74 65 72 3E 3C 54 41 42 4C 45 20 73 74 79 6C 65 3D 5C 22 42 4F 52 44 45 52 2D 43 4F 4C 4C 41 50 53 45 3A 20 63 6F 6C 6C 61 70 73 65 5C 22 20 68 65 69 67 68 74 3D 31 20 63 65 6C 6C 53 70 61 63 69 6E 67 3D 30 20 62 6F 72 64 65 72}

	condition:
		all of them
}

rule WebShell_Generic_PHP_10
{
	meta:
		description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php, PHPRemoteView.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
		hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
		hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
		hash3 = "7d5b54c7cab6b82fb7d131d7bbb989fd53cb1b57"

	strings:
		$s2 = {24 77 6F 72 6C 64 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 77 6F 72 6C 64 5B 27 65 78 65 63 75 74 65 27 5D 3D 3D 27 78 27 29 20 3F 20 27 74 27 20 3A 20 27 54 27 3B 20}
		$s6 = {24 6F 77 6E 65 72 5B 5C 22 77 72 69 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 32 30 30 29 20 3F 20 27 77 27 20 3A 20 27 2D 27 3B 20}
		$s11 = {24 77 6F 72 6C 64 5B 5C 22 65 78 65 63 75 74 65 5C 22 5D 20 3D 20 28 24 6D 6F 64 65 20 26 20 30 30 30 30 31 29 20 3F 20 27 78 27 20 3A 20 27 2D 27 3B 20}
		$s12 = {65 6C 73 65 20 69 66 28 20 24 6D 6F 64 65 20 26 20 30 78 41 30 30 30 20 29 20}
		$s17 = {24 73 3D 73 70 72 69 6E 74 66 28 5C 22 25 31 73 5C 22 2C 20 24 74 79 70 65 29 3B 20}
		$s20 = {66 6F 6E 74 2D 73 69 7A 65 3A 20 38 70 74 3B}

	condition:
		all of them
}

rule WebShell_Generic_PHP_11
{
	meta:
		description = "PHP Webshells Github Archive - from files rootshell.php, Rootshell.v.1.0.php, s72 Shell v1.1 Coding.php, s72_Shell_v1.1_Coding.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "31a82cbee8dffaf8eb7b73841f3f3e8e9b3e78cf"
		hash1 = "838c7191cb10d5bb0fc7460b4ad0c18c326764c6"
		hash2 = "8dfcd919d8ddc89335307a7b2d5d467b1fd67351"
		hash3 = "80aba3348434c66ac471daab949871ab16c50042"

	strings:
		$s5 = {24 66 69 6C 65 6E 61 6D 65 20 3D 20 24 62 61 63 6B 75 70 73 74 72 69 6E 67 2E 5C 22 24 66 69 6C 65 6E 61 6D 65 5C 22 3B}
		$s6 = {77 68 69 6C 65 20 28 24 66 69 6C 65 20 3D 20 72 65 61 64 64 69 72 28 24 66 6F 6C 64 65 72 29 29 20 7B}
		$s7 = {69 66 28 24 66 69 6C 65 20 21 3D 20 5C 22 2E 5C 22 20 26 26 20 24 66 69 6C 65 20 21 3D 20 5C 22 2E 2E 5C 22 29}
		$s9 = {24 62 61 63 6B 75 70 73 74 72 69 6E 67 20 3D 20 5C 22 63 6F 70 79 5F 6F 66 5F 5C 22 3B}
		$s10 = {69 66 28 20 66 69 6C 65 5F 65 78 69 73 74 73 28 24 66 69 6C 65 5F 6E 61 6D 65 29 29}
		$s13 = {67 6C 6F 62 61 6C 20 24 66 69 6C 65 5F 6E 61 6D 65 2C 20 24 66 69 6C 65 6E 61 6D 65 3B}
		$s16 = {63 6F 70 79 28 24 66 69 6C 65 2C 5C 22 24 66 69 6C 65 6E 61 6D 65 5C 22 29 3B}
		$s18 = {3C 74 64 20 77 69 64 74 68 3D 5C 22 34 39 25 5C 22 20 68 65 69 67 68 74 3D 5C 22 31 34 32 5C 22 3E}

	condition:
		all of them
}

rule WebShell__findsock_php_findsock_shell_php_reverse_shell
{
	meta:
		description = "PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "5622c9841d76617bfc3cd4cab1932d8349b7044f"
		hash1 = "4a20f36035bbae8e342aab0418134e750b881d05"
		hash2 = "40dbdc0bdf5218af50741ba011c5286a723fa9bf"

	strings:
		$s1 = {2F 2F 20 6D 65 20 61 74 20 70 65 6E 74 65 73 74 6D 6F 6E 6B 65 79 40 70 65 6E 74 65 73 74 6D 6F 6E 6B 65 79 2E 6E 65 74}

	condition:
		all of them
}

rule WebShell_Generic_PHP_6
{
	meta:
		description = "PHP Webshells Github Archive - from files c0derz shell [csh] v. 0.1.1 release.php, CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "1a08f5260c4a2614636dfc108091927799776b13"
		hash1 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash2 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

	strings:
		$s2 = {40 65 76 61 6C 28 73 74 72 69 70 73 6C 61 73 68 65 73 28 24 5F 50 4F 53 54 5B 27 70 68 70 63 6F 64 65 27 5D 29 29 3B}
		$s5 = {65 63 68 6F 20 73 68 65 6C 6C 5F 65 78 65 63 28 24 63 6F 6D 29 3B}
		$s7 = {69 66 28 24 73 65 72 74 79 70 65 20 3D 3D 20 5C 22 77 69 6E 64 61 5C 22 29 7B}
		$s8 = {66 75 6E 63 74 69 6F 6E 20 65 78 65 63 75 74 65 28 24 63 6F 6D 29}
		$s12 = {65 63 68 6F 20 64 65 63 6F 64 65 28 65 78 65 63 75 74 65 28 24 63 6D 64 29 29 3B}
		$s15 = {65 63 68 6F 20 73 79 73 74 65 6D 28 24 63 6F 6D 29 3B}

	condition:
		4 of them
}

rule Unpack_Injectt
{
	meta:
		description = "Webshells Auto-generated - file Injectt.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8a5d2158a566c87edc999771e12d42c5"

	strings:
		$s2 = {25 73 20 2D 52 75 6E 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2D 2D 3E 54 6F 20 49 6E 73 74 61 6C 6C 20 41 6E 64 20 52 75 6E 20 54 68 65 20 53 65 72 76 69 63 65}
		$s3 = {25 73 20 2D 55 6E 69 6E 73 74 61 6C 6C 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2D 2D 3E 54 6F 20 55 6E 69 6E 73 74 61 6C 6C 20 54 68 65 20 53 65 72 76 69 63 65}
		$s4 = {28 53 54 41 4E 44 41 52 44 5F 52 49 47 48 54 53 5F 52 45 51 55 49 52 45 44 20 7C 53 43 5F 4D 41 4E 41 47 45 52 5F 43 4F 4E 4E 45 43 54 20 7C 53 43 5F 4D 41 4E 41 47 45 52 5F 43 52 45 41 54 45 5F 53 45 52 56 49 43 45 20 7C 53 43 5F 4D 41 4E}

	condition:
		all of them
}

rule HYTop_DevPack_fso
{
	meta:
		description = "Webshells Auto-generated - file fso.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b37f3cde1a08890bd822a182c3a881f6"

	strings:
		$s0 = {3C 21 2D 2D 20 50 61 67 65 46 53 4F 20 42 65 6C 6F 77 20 2D 2D 3E}
		$s1 = {74 68 65 46 69 6C 65 2E 77 72 69 74 65 4C 69 6E 65 28 5C 22 3C 73 63 72 69 70 74 20 6C 61 6E 67 75 61 67 65 3D 5C 22 5C 22 76 62 73 63 72 69 70 74 5C 22 5C 22 20 72 75 6E 61 74 3D 73 65 72 76 65 72 3E 69 66 20 72 65 71 75 65 73 74 28 5C 22 5C 22 5C 22 26 63 6C 69}

	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_ssh
{
	meta:
		description = "Webshells Auto-generated - file ssh.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1aa5307790d72941589079989b4f900e"

	strings:
		$s0 = {65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 73 74 72 5F 72 6F 74 31 33 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 27}

	condition:
		all of them
}

rule Debug_BDoor
{
	meta:
		description = "Webshells Auto-generated - file BDoor.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "e4e8e31dd44beb9320922c5f49739955"

	strings:
		$s1 = {5C 5C 42 44 6F 6F 72 5C 5C}
		$s4 = {53 4F 46 54 57 41 52 45 5C 5C 4D 69 63 72 6F 73 6F 66 74 5C 5C 57 69 6E 64 6F 77 73 5C 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 5C 52 75 6E}

	condition:
		all of them
}

rule bin_Client
{
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5f91a5b46d155cacf0cc6673a2a5461b"

	strings:
		$s0 = {52 65 63 69 65 76 65 64 20 72 65 73 70 6F 6E 64 20 66 72 6F 6D 20 73 65 72 76 65 72 21 21}
		$s4 = {70 61 63 6B 65 74 20 64 6F 6F 72 20 63 6C 69 65 6E 74}
		$s5 = {69 6E 70 75 74 20 73 6F 75 72 63 65 20 70 6F 72 74 28 77 68 61 74 65 76 65 72 20 79 6F 75 20 77 61 6E 74 29 3A}
		$s7 = {50 61 63 6B 65 74 20 73 65 6E 74 2C 77 61 69 74 69 6E 67 20 66 6F 72 20 72 65 70 6C 79 2E 2E 2E}

	condition:
		all of them
}

rule ZXshell2_0_rar_Folder_ZXshell
{
	meta:
		description = "Webshells Auto-generated - file ZXshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "246ce44502d2f6002d720d350e26c288"

	strings:
		$s0 = {57 50 72 65 76 69 65 77 50 61 67 65 73 6E}
		$s1 = {44 41 21 4F 4C 55 54 45 4C 59 20 4E}

	condition:
		all of them
}

rule RkNTLoad
{
	meta:
		description = "Webshells Auto-generated - file RkNTLoad.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "262317c95ced56224f136ba532b8b34f"

	strings:
		$s1 = {24 49 6E 66 6F 3A 20 54 68 69 73 20 66 69 6C 65 20 69 73 20 70 61 63 6B 65 64 20 77 69 74 68 20 74 68 65 20 55 50 58 20 65 78 65 63 75 74 61 62 6C 65 20 70 61 63 6B 65 72 20 68 74 74 70 3A 2F 2F 75 70 78 2E 74 73 78 2E 6F 72 67 20 24}
		$s2 = {35 70 75 72 2B 76 69 72 74 75 21}
		$s3 = {75 67 68 20 73 70 61 63 23 6E}
		$s4 = {78 63 45 78 33 57 72 69 4C 34}
		$s5 = {72 75 6E 74 69 6D 65 20 65 72 72 6F 72}
		$s6 = {6C 6F 73 65 48 57 61 69 74 2E 53 72 2E}
		$s7 = {65 73 73 61 67 65 42 6F 78 41 77}
		$s8 = {24 49 64 3A 20 55 50 58 20 31 2E 30 37 20 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 31 39 39 36 2D 32 30 30 31 20 74 68 65 20 55 50 58 20 54 65 61 6D 2E 20 41 6C 6C 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2E 20 24}

	condition:
		all of them
}

rule binder2_binder2
{
	meta:
		description = "Webshells Auto-generated - file binder2.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d594e90ad23ae0bc0b65b59189c12f11"

	strings:
		$s0 = {49 73 43 68 61 72 41 6C 70 68 61 4E 75 6D 65 72 69 63 41}
		$s2 = {57 69 64 65 43 68 61 72 54 6F 4D}
		$s4 = {67 20 35 70 75 72 2B 76 69 72 74 75 21}
		$s5 = {5C 5C 73 79 73 6C 6F 67 2E 65 6E}
		$s6 = {68 65 61 70 37 27 37 6F 71 6B 3F 6E 6F 74 3D}
		$s8 = {2D 20 4B 61 62 6C 74 6F 20 69 6E}

	condition:
		all of them
}

rule thelast_orice2
{
	meta:
		description = "Webshells Auto-generated - file orice2.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "aa63ffb27bde8d03d00dda04421237ae"

	strings:
		$s0 = {20 24 61 61 20 3D 20 24 5F 47 45 54 5B 27 61 61 27 5D 3B}
		$s1 = {65 63 68 6F 20 24 61 61 3B}

	condition:
		all of them
}

rule FSO_s_sincap
{
	meta:
		description = "Webshells Auto-generated - file sincap.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "dc5c2c2392b84a1529abd92e98e9aa5b"

	strings:
		$s0 = {20 20 20 20 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 5C 22 23 45 35 45 35 45 35 5C 22 20 73 74 79 6C 65 3D 5C 22 66 6F 6E 74 2D 73 69 7A 65 3A 20 38 70 74 3B 20 66 6F 6E 74 2D 77 65 69 67 68 74 3A 20 37 30 30 5C 22 20 66 61 63 65 3D 5C 22 41 72 69 61 6C 5C 22 3E}
		$s4 = {3C 62 6F 64 79 20 74 65 78 74 3D 5C 22 23 30 30 38 30 30 30 5C 22 20 62 67 63 6F 6C 6F 72 3D 5C 22 23 38 30 38 30 38 30 5C 22 20 74 6F 70 6D 61 72 67 69 6E 3D 5C 22 30 5C 22 20 6C 65 66 74 6D 61 72 67 69 6E 3D 5C 22 30 5C 22 20 72 69 67 68 74 6D 61 72 67 69 6E 3D}

	condition:
		all of them
}

rule PhpShell
{
	meta:
		description = "Webshells Auto-generated - file PhpShell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "539baa0d39a9cf3c64d65ee7a8738620"

	strings:
		$s2 = {68 72 65 66 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 67 69 6D 70 73 74 65 72 2E 63 6F 6D 2F 77 69 6B 69 2F 50 68 70 53 68 65 6C 6C 5C 22 3E 77 77 77 2E 67 69 6D 70 73 74 65 72 2E 63 6F 6D 2F 77 69 6B 69 2F 50 68 70 53 68 65 6C 6C 3C 2F 61 3E 2E}

	condition:
		all of them
}

rule HYTop_DevPack_config
{
	meta:
		description = "Webshells Auto-generated - file config.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b41d0e64e64a685178a3155195921d61"

	strings:
		$s0 = {63 6F 6E 73 74 20 61 64 6D 69 6E 50 61 73 73 77 6F 72 64 3D 5C 22}
		$s2 = {63 6F 6E 73 74 20 75 73 65 72 50 61 73 73 77 6F 72 64 3D 5C 22}
		$s3 = {63 6F 6E 73 74 20 6D 56 65 72 73 69 6F 6E 3D}

	condition:
		all of them
}

rule sendmail
{
	meta:
		description = "Webshells Auto-generated - file sendmail.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "75b86f4a21d8adefaf34b3a94629bd17"

	strings:
		$s3 = {5F 4E 65 78 74 50 79 43 38 30 38}
		$s6 = {43 6F 70 79 72 69 67 68 74 20 28 43 29 20 32 30 30 30 2C 20 44 69 61 6D 6F 6E 64 20 43 6F 6D 70 75 74 65 72 20 53 79 73 74 65 6D 73 20 50 74 79 2E 20 4C 74 64 2E 20 28 77 77 77 2E 64 69 61 6D 6F 6E 64 63 73 2E 63 6F 6D 2E 61 75 29}

	condition:
		all of them
}

rule FSO_s_zehir4
{
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5b496a61363d304532bcf52ee21f5d55"

	strings:
		$s5 = {20 62 79 4D 65 73 61 6A 20}

	condition:
		all of them
}

rule hkshell_hkshell
{
	meta:
		description = "Webshells Auto-generated - file hkshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "168cab58cee59dc4706b3be988312580"

	strings:
		$s1 = {50 72 53 65 73 73 4B 45 52 4E 45 4C 55}
		$s2 = {43 75 72 33 6E 74 56 37 73 69 6F 6E}
		$s3 = {45 78 70 6C 6F 72 65 72 38}

	condition:
		all of them
}

rule iMHaPFtp
{
	meta:
		description = "Webshells Auto-generated - file iMHaPFtp.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "12911b73bc6a5d313b494102abcf5c57"

	strings:
		$s1 = {65 63 68 6F 20 5C 22 5C 5C 74 3C 74 68 20 63 6C 61 73 73 3D 5C 5C 5C 22 70 65 72 6D 69 73 73 69 6F 6E 5F 68 65 61 64 65 72 5C 5C 5C 22 3E 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 24 73 65 6C 66 3F 7B 24 64 7D 73 6F 72 74 3D 70 65 72 6D 69 73 73 69 6F 6E 24 72 5C 5C 5C 22 3E}

	condition:
		all of them
}

rule Unpack_TBack
{
	meta:
		description = "Webshells Auto-generated - file TBack.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a9d1007823bf96fb163ab38726b48464"

	strings:
		$s5 = {5C 5C 66 69 6E 61 6C 5C 5C 6E 65 77 5C 5C 6C 63 63 5C 5C 70 75 62 6C 69 63 2E 64 6C 6C}

	condition:
		all of them
}

rule DarkSpy105
{
	meta:
		description = "Webshells Auto-generated - file DarkSpy105.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f0b85e7bec90dba829a3ede1ab7d8722"

	strings:
		$s7 = {53 6F 72 72 79 2C 44 61 72 6B 53 70 79 20 67 6F 74 20 61 6E 20 75 6E 6B 6E 6F 77 6E 20 65 78 63 65 70 74 69 6F 6E 2C 70 6C 65 61 73 65 20 72 65 2D 72 75 6E 20 69 74 2C 74 68 61 6E 6B 73 21}

	condition:
		all of them
}

rule EditServer_Webshell
{
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f945de25e0eba3bdaf1455b3a62b9832"

	strings:
		$s2 = {53 65 72 76 65 72 20 25 73 20 48 61 76 65 20 42 65 65 6E 20 43 6F 6E 66 69 67 75 72 65 64}
		$s5 = {54 68 65 20 53 65 72 76 65 72 20 50 61 73 73 77 6F 72 64 20 45 78 63 65 65 64 73 20 33 32 20 43 68 61 72 61 63 74 65 72 73}
		$s8 = {39 2D 2D 53 65 74 20 50 72 6F 63 65 63 65 73 73 20 4E 61 6D 65 20 54 6F 20 49 6E 6A 65 63 74 20 44 4C 4C}

	condition:
		all of them
}

rule FSO_s_reader
{
	meta:
		description = "Webshells Auto-generated - file reader.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"

	strings:
		$s2 = {6D 61 69 6C 74 6F 3A 6D 61 69 6C 62 6F 6D 62 40 68 6F 74 6D 61 69 6C 2E}

	condition:
		all of them
}

rule ASP_CmdAsp
{
	meta:
		description = "Webshells Auto-generated - file CmdAsp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "79d4f3425f7a89befb0ef3bafe5e332f"

	strings:
		$s2 = {27 20 2D 2D 20 52 65 61 64 20 74 68 65 20 6F 75 74 70 75 74 20 66 72 6F 6D 20 6F 75 72 20 63 6F 6D 6D 61 6E 64 20 61 6E 64 20 72 65 6D 6F 76 65 20 74 68 65 20 74 65 6D 70 20 66 69 6C 65 20 2D 2D 20 27}
		$s6 = {43 61 6C 6C 20 6F 53 63 72 69 70 74 2E 52 75 6E 20 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 65 6D 70 46 69 6C 65 2C 20 30 2C 20 54 72 75 65 29}
		$s9 = {27 20 2D 2D 20 63 72 65 61 74 65 20 74 68 65 20 43 4F 4D 20 6F 62 6A 65 63 74 73 20 74 68 61 74 20 77 65 20 77 69 6C 6C 20 62 65 20 75 73 69 6E 67 20 2D 2D 20 27}

	condition:
		all of them
}

rule KA_uShell
{
	meta:
		description = "Webshells Auto-generated - file KA_uShell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "685f5d4f7f6751eaefc2695071569aab"

	strings:
		$s5 = {69 66 28 65 6D 70 74 79 28 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 41 55 54 48 5F 50 57 27 5D 29 20 7C 7C 20 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 41 55 54 48 5F 50 57 27 5D 3C 3E 24 70 61 73 73}
		$s6 = {69 66 20 28 24 5F 50 4F 53 54 5B 27 70 61 74 68 27 5D 3D 3D 5C 22 5C 22 29 7B 24 75 70 6C 6F 61 64 66 69 6C 65 20 3D 20 24 5F 46 49 4C 45 53 5B 27 66 69 6C 65 27 5D 5B 27 6E 61 6D 65 27 5D 3B 7D}

	condition:
		all of them
}

rule PHP_Backdoor_v1
{
	meta:
		description = "Webshells Auto-generated - file PHP Backdoor v1.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0506ba90759d11d78befd21cabf41f3d"

	strings:
		$s5 = {65 63 68 6F 5C 22 3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 5C 5C 5C 22 50 4F 53 54 5C 5C 5C 22 20 61 63 74 69 6F 6E 3D 5C 5C 5C 22 5C 22 2E 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 53 45 4C 46 27 5D 2E 5C 22 3F 65 64 69 74 3D 5C 22 2E 24 74 68}
		$s8 = {65 63 68 6F 20 5C 22 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 5C 22 2E 24 5F 53 45 52 56 45 52 5B 27 50 48 50 5F 53 45 4C 46 27 5D 2E 5C 22 3F 70 72 6F 78 79}

	condition:
		all of them
}

rule svchostdll
{
	meta:
		description = "Webshells Auto-generated - file svchostdll.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0f6756c8cb0b454c452055f189e4c3f4"

	strings:
		$s0 = {49 6E 73 74 61 6C 6C 53 65 72 76 69 63 65}
		$s1 = {52 75 6E 64 6C 6C 49 6E 73 74 61 6C 6C 41}
		$s2 = {55 6E 69 6E 73 74 61 6C 6C 53 65 72 76 69 63 65}
		$s3 = {26 47 33 20 55 73 65 72 73 20 49 6E 20 52 65 67 69 73 74 72 79 44}
		$s4 = {4F 4C 5F 53 48 55 54 44 4F 57 4E 3B 49}
		$s5 = {53 76 63 48 6F 73 74 44 4C 4C 2E 64 6C 6C}
		$s6 = {52 75 6E 64 6C 6C 55 6E 69 6E 73 74 61 6C 6C 41}
		$s7 = {49 6E 74 65 72 6E 65 74 4F 70 65 6E 41}
		$s8 = {43 68 65 63 6B 20 43 6C 6F 6E 65 6F 6D 70 6C 65 74 65}

	condition:
		all of them
}

rule HYTop_DevPack_server
{
	meta:
		description = "Webshells Auto-generated - file server.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1d38526a215df13c7373da4635541b43"

	strings:
		$s0 = {3C 21 2D 2D 20 50 61 67 65 53 65 72 76 65 72 20 42 65 6C 6F 77 20 2D 2D 3E}

	condition:
		all of them
}

rule vanquish
{
	meta:
		description = "Webshells Auto-generated - file vanquish.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "684450adde37a93e8bb362994efc898c"

	strings:
		$s3 = {59 6F 75 20 63 61 6E 6E 6F 74 20 64 65 6C 65 74 65 20 70 72 6F 74 65 63 74 65 64 20 66 69 6C 65 73 2F 66 6F 6C 64 65 72 73 21 20 49 6E 73 74 65 61 64 2C 20 79 6F 75 72 20 61 74 74 65 6D 70 74 20 68 61 73 20 62 65 65 6E 20 6C 6F 67 67 65 64}
		$s8 = {3F 56 43 72 65 61 74 65 50 72 6F 63 65 73 73 41 40 40 59 47 48 50 42 44 50 41 44 50 41 55 5F 53 45 43 55 52 49 54 59 5F 41 54 54 52 49 42 55 54 45 53 40 40 32 48 4B 50 41 58 30 50 41 55 5F 53 54 41 52 54 55 50 49 4E 46 4F 41 40 40 50 41 55}
		$s9 = {3F 56 46 69 6E 64 46 69 72 73 74 46 69 6C 65 45 78 57 40 40 59 47 50 41 58 50 42 47 57 34 5F 46 49 4E 44 45 58 5F 49 4E 46 4F 5F 4C 45 56 45 4C 53 40 40 50 41 58 57 34 5F 46 49 4E 44 45 58 5F 53 45 41 52 43 48 5F 4F 50 53 40 40 32 4B 40 5A}

	condition:
		all of them
}

rule winshell
{
	meta:
		description = "Webshells Auto-generated - file winshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3144410a37dd4c29d004a814a294ea26"

	strings:
		$s0 = {53 6F 66 74 77 61 72 65 5C 5C 4D 69 63 72 6F 73 6F 66 74 5C 5C 57 69 6E 64 6F 77 73 5C 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 5C 52 75 6E 53 65 72 76 69 63 65 73}
		$s1 = {57 69 6E 53 68 65 6C 6C 20 53 65 72 76 69 63 65}
		$s2 = {5F 5F 47 4C 4F 42 41 4C 5F 48 45 41 50 5F 53 45 4C 45 43 54 45 44}
		$s3 = {5F 5F 4D 53 56 43 52 54 5F 48 45 41 50 5F 53 45 4C 45 43 54}
		$s4 = {50 72 6F 76 69 64 65 20 57 69 6E 64 6F 77 73 20 43 6D 64 53 68 65 6C 6C 20 53 65 72 76 69 63 65}
		$s5 = {55 52 4C 44 6F 77 6E 6C 6F 61 64 54 6F 46 69 6C 65 41}
		$s6 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6F 63 65 73 73}
		$s7 = {47 65 74 4D 6F 64 75 6C 65 42 61 73 65 4E 61 6D 65 41}
		$s8 = {57 69 6E 53 68 65 6C 6C 20 76 35 2E 30 20 28 43 29 32 30 30 32 20 6A 61 6E 6B 65 72 2E 6F 72 67}

	condition:
		all of them
}

rule FSO_s_remview
{
	meta:
		description = "Webshells Auto-generated - file remview.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b4a09911a5b23e00b55abe546ded691c"

	strings:
		$s2 = {20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 68 72 20 73 69 7A 65 3D 31 20 6E 6F 73 68 61 64 65 3E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 22}
		$s3 = {20 20 20 20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 73 63 72 69 70 74 3E 73 74 72 24 69 3D 5C 5C 5C 22 5C 22 2E 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 22 5C 22 2C 5C 22 5C 5C 5C 5C 5C 5C 5C 22 5C 22 2C 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 22 2C 5C 22 5C 5C 5C 5C 5C 5C 5C 5C 5C 22}
		$s4 = {20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 68 72 20 73 69 7A 65 3D 31 20 6E 6F 73 68 61 64 65 3E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 5C 5C 6E 3C}

	condition:
		all of them
}

rule saphpshell
{
	meta:
		description = "Webshells Auto-generated - file saphpshell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d7bba8def713512ddda14baf9cd6889a"

	strings:
		$s0 = {3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 63 6F 6D 6D 61 6E 64 5C 22 20 73 69 7A 65 3D 5C 22 36 30 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 3F 3D 24 5F 50 4F 53 54 5B 27 63 6F 6D 6D 61 6E 64 27 5D 3F 3E}

	condition:
		all of them
}

rule HYTop2006_rar_Folder_2006Z
{
	meta:
		description = "Webshells Auto-generated - file 2006Z.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "fd1b6129abd4ab177fed135e3b665488"

	strings:
		$s1 = {77 61 6E 67 79 6F 6E 67 2C 63 7A 79 2C 61 6C 6C 65 6E 2C 6C 63 78 2C 4D 61 72 63 6F 73 2C 6B 45 76 69 6E 31 39 38 36 2C 6D 79 74 68}
		$s8 = {53 79 73 74 65 6D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 43 6F 6E 74 72 6F 6C 5C 5C 4B 65 79 62 6F 61 72 64 20 4C 61 79 6F 75 74 73 5C 5C 25 2E 38 78}

	condition:
		all of them
}

rule admin_ad
{
	meta:
		description = "Webshells Auto-generated - file admin-ad.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "e6819b8f8ff2f1073f7d46a0b192f43b"

	strings:
		$s6 = {3C 74 64 20 61 6C 69 67 6E 3D 5C 22 63 65 6E 74 65 72 5C 22 3E 20 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 63 6D 64 5C 22 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 69 64 3D 5C 22 63 6D 64 5C 22 20 73 69 7A}
		$s7 = {52 65 73 70 6F 6E 73 65 2E 77 72 69 74 65 5C 22 3C 61 20 68 72 65 66 3D 27 5C 22 26 75 72 6C 26 5C 22 3F 70 61 74 68 3D 5C 22 26 52 65 71 75 65 73 74 28 5C 22 6F 6C 64 70 61 74 68 5C 22 29 26 5C 22 26 61 74 74 72 69 62 3D 5C 22 26 61 74 74 72 69 62 26 5C 22 27 3E 3C}

	condition:
		all of them
}

rule FSO_s_casus15
{
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8d155b4239d922367af5d0a1b89533a3"

	strings:
		$s6 = {69 66 28 28 69 73 5F 64 69 72 28 5C 22 24 64 65 6C 64 69 72 2F 24 66 69 6C 65 5C 22 29 29 20 41 4E 44 20 28 24 66 69 6C 65 21 3D 5C 22 2E 5C 22 29 20 41 4E 44 20 28 24 66 69 6C 65 21 3D 5C 22 2E 2E 5C 22 29 29}

	condition:
		all of them
}

rule BIN_Client
{
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "9f0a74ec81bc2f26f16c5c172b80eca7"

	strings:
		$s0 = {3D 3D 3D 3D 3D 52 65 6D 6F 74 65 20 53 68 65 6C 6C 20 43 6C 6F 73 65 64 3D 3D 3D 3D 3D}
		$s2 = {41 6C 6C 20 46 69 6C 65 73 28 2A 2E 2A 29 7C 2A 2E 2A 7C 7C}
		$s6 = {57 53 41 53 74 61 72 74 75 70 20 45 72 72 6F 72 21}
		$s7 = {53 48 47 65 74 46 69 6C 65 49 6E 66 6F 41}
		$s8 = {43 72 65 61 74 65 54 68 72 65 61 64 20 46 61 6C 73 65 21}
		$s9 = {50 6F 72 74 20 4E 75 6D 62 65 72 20 45 72 72 6F 72}

	condition:
		4 of them
}

rule shelltools_g0t_root_uptime
{
	meta:
		description = "Webshells Auto-generated - file uptime.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d1f56102bc5d3e2e37ab3ffa392073b9"

	strings:
		$s0 = {4A 44 69 61 6D 6F 6E 64 43 53 6C 43 7E}
		$s1 = {43 68 61 72 61 63 74 51 41}
		$s2 = {24 49 6E 66 6F 3A 20 54 68 69 73 20 66 69 6C 65 20 69 73 20 70 61 63 6B 65 64 20 77 69 74 68 20 74 68 65 20 55 50 58 20 65 78 65 63 75 74 61 62 6C 65 20 70 61 63 6B 65 72 20 24}
		$s5 = {48 61 6E 64 6C 65 72 65 61 74 65 43 6F 6E 73 6F}
		$s7 = {49 4F 4E 5C 5C 53 79 73 74 65 6D 5C 5C 46 6C 6F 61 74 69 6E 67 50 6F}

	condition:
		all of them
}

rule Simple_PHP_BackDooR
{
	meta:
		description = "Webshells Auto-generated - file Simple_PHP_BackDooR.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a401132363eecc3a1040774bec9cb24f"

	strings:
		$s0 = {3C 68 72 3E 74 6F 20 62 72 6F 77 73 65 20 67 6F 20 74 6F 20 68 74 74 70 3A 2F 2F 3C 3F 20 65 63 68 6F 20 24 53 45 52 56 45 52 5F 4E 41 4D 45 2E 24 52 45 51 55 45 53 54 5F 55 52 49 3B 20 3F 3E 3F 64 3D 5B 64 69 72 65 63 74 6F 72 79 20 68 65}
		$s6 = {69 66 28 21 6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 48 54 54 50 5F 50 4F 53 54 5F 46 49 4C 45 53 5B 27 66 69 6C 65 5F 6E 61 6D 65 27 5D 5B 27 74 6D 70 5F 6E 61 6D 65 27 5D 2C 20 24 64 69 72 2E 24 66 6E}
		$s9 = {2F 2F 20 61 20 73 69 6D 70 6C 65 20 70 68 70 20 62 61 63 6B 64 6F 6F 72}

	condition:
		1 of them
}

rule sig_2005Gray
{
	meta:
		description = "Webshells Auto-generated - file 2005Gray.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "75dbe3d3b70a5678225d3e2d78b604cc"

	strings:
		$s0 = {53 43 52 4F 4C 4C 42 41 52 2D 46 41 43 45 2D 43 4F 4C 4F 52 3A 20 23 65 38 65 37 65 37 3B}
		$s4 = {65 63 68 6F 20 5C 22 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 22 5C 22 2F 5C 22 26 65 6E 63 6F 64 65 46 6F 72 55 72 6C 28 74 68 65 48 72 65 66 2C 66 61 6C 73 65 29 26 5C 22 5C 22 5C 22 20 74 61 72 67 65 74 3D 5F 62 6C 61 6E 6B 3E 5C 22 26 72 65 70 6C 61 63 65}
		$s8 = {74 68 65 48 72 65 66 3D 6D 69 64 28 72 65 70 6C 61 63 65 28 6C 63 61 73 65 28 6C 69 73 74 2E 70 61 74 68 29 2C 6C 63 61 73 65 28 73 65 72 76 65 72 2E 6D 61 70 50 61 74 68 28 5C 22 2F 5C 22 29 29 2C 5C 22 5C 22 29 2C 32 29}
		$s9 = {53 43 52 4F 4C 4C 42 41 52 2D 33 44 4C 49 47 48 54 2D 43 4F 4C 4F 52 3A 20 23 63 63 63 63 63 63 3B}

	condition:
		all of them
}

rule DllInjection
{
	meta:
		description = "Webshells Auto-generated - file DllInjection.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a7b92283a5102886ab8aee2bc5c8d718"

	strings:
		$s0 = {5C 5C 42 44 6F 6F 72 5C 5C 44 6C 6C 49 6E 6A 65 63 74 69}

	condition:
		all of them
}

rule Mithril_v1_45_Mithril
{
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f1484f882dc381dde6eaa0b80ef64a07"

	strings:
		$s2 = {63 72 65 73 73 2E 65 78 65}
		$s7 = {5C 5C 44 65 62 75 67 5C 5C 4D 69 74 68 72 69 6C 2E}

	condition:
		all of them
}

rule hkshell_hkrmv
{
	meta:
		description = "Webshells Auto-generated - file hkrmv.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "bd3a0b7a6b5536f8d96f50956560e9bf"

	strings:
		$s5 = {2F 54 48 55 4D 42 50 4F 53 49 54 49 4F 4E 37}
		$s6 = {5C 5C 45 76 69 6C 42 6C 61 64 65 5C 5C}

	condition:
		all of them
}

rule phpshell
{
	meta:
		description = "Webshells Auto-generated - file phpshell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1dccb1ea9f24ffbd085571c88585517b"

	strings:
		$s1 = {65 63 68 6F 20 5C 22 3C 69 6E 70 75 74 20 73 69 7A 65 3D 5C 5C 5C 22 31 30 30 5C 5C 5C 22 20 74 79 70 65 3D 5C 5C 5C 22 74 65 78 74 5C 5C 5C 22 20 6E 61 6D 65 3D 5C 5C 5C 22 6E 65 77 66 69 6C 65 5C 5C 5C 22 20 76 61 6C 75 65 3D 5C 5C 5C 22 24 69 6E 70 75 74 66 69 6C 65 5C 5C 5C 22 3E 3C 62}
		$s2 = {24 69 6D 67 5B 24 69 64 5D 20 3D 20 5C 22 3C 69 6D 67 20 68 65 69 67 68 74 3D 5C 5C 5C 22 31 36 5C 5C 5C 22 20 77 69 64 74 68 3D 5C 5C 5C 22 31 36 5C 5C 5C 22 20 62 6F 72 64 65 72 3D 5C 5C 5C 22 30 5C 5C 5C 22 20 73 72 63 3D 5C 5C 5C 22 24 52 45 4D 4F 54 45 5F 49 4D 41 47 45 5F 55 52}
		$s3 = {24 66 69 6C 65 20 3D 20 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 22 2C 20 5C 22 2F 5C 22 2C 20 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 2F 2F 5C 22 2C 20 5C 22 2F 5C 22 2C 20 73 74 72 5F 72 65 70 6C 61 63 65 28 5C 22 5C 5C 5C 5C 5C 5C 5C 5C 5C 22 2C 20 5C 22 5C 5C 5C 5C 5C 22 2C 20}

	condition:
		all of them
}

// duplicated
/* rule FSO_s_cmd
{
	meta:
		description = "Webshells Auto-generated - file cmd.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cbe8e365d41dd3cd8e462ca434cf385f"

	strings:
		$s0 = {3C 25 3D 20 5C 22 5C 5C 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26 20 5C 22 5C 5C 5C 22 20 26 20 6F 53 63 72 69 70 74 4E 65 74 2E 55 73 65 72 4E 61 6D 65 20 25 3E}
		$s1 = {43 61 6C 6C 20 6F 53 63 72 69 70 74 2E 52 75 6E 20 28 5C 22 63 6D 64 2E 65 78 65 20 2F 63 20 5C 22 20 26 20 73 7A 43 4D 44 20 26 20 5C 22 20 3E 20 5C 22 20 26 20 73 7A 54 65 6D 70 46 69 6C 65 2C 20 30 2C 20 54 72 75 65 29}

	condition:
		all of them
}*/

rule FeliksPack3___PHP_Shells_phpft
{
	meta:
		description = "Webshells Auto-generated - file phpft.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "60ef80175fcc6a879ca57c54226646b1"

	strings:
		$s6 = {50 48 50 20 46 69 6C 65 73 20 54 68 69 65 66}
		$s11 = {68 74 74 70 3A 2F 2F 77 77 77 2E 34 6E 67 65 6C 2E 6E 65 74}

	condition:
		all of them
}

rule FSO_s_indexer
{
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "135fc50f85228691b401848caef3be9e"

	strings:
		$s3 = {3C 74 64 3E 4E 65 72 65 79 65 20 3A 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 6E 65 72 65 79 65 5C 22 20 73 69 7A 65 3D 32 35 3E 3C 2F 74 64 3E 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 72}

	condition:
		all of them
}

rule r57shell
{
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8023394542cddf8aee5dec6072ed02b5"

	strings:
		$s11 = {20 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 3D 5C 22 65 63 68 6F 20 5C 5C 5C 22 4E 6F 77 20 73 63 72 69 70 74 20 74 72 79 20 63 6F 6E 6E 65 63 74 20 74 6F}

	condition:
		all of them
}

rule bdcli100
{
	meta:
		description = "Webshells Auto-generated - file bdcli100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b12163ac53789fb4f62e4f17a8c2e028"

	strings:
		$s5 = {75 6E 61 62 6C 65 20 74 6F 20 63 6F 6E 6E 65 63 74 20 74 6F 20}
		$s8 = {62 61 63 6B 64 6F 6F 72 20 69 73 20 63 6F 72 72 75 70 74 65 64 20 6F 6E 20}

	condition:
		all of them
}

rule HYTop_DevPack_2005Red
{
	meta:
		description = "Webshells Auto-generated - file 2005Red.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d8ccda2214b3f6eabd4502a050eb8fe8"

	strings:
		$s0 = {73 63 72 6F 6C 6C 62 61 72 2D 64 61 72 6B 73 68 61 64 6F 77 2D 63 6F 6C 6F 72 3A 23 46 46 39 44 42 42 3B}
		$s3 = {65 63 68 6F 20 5C 22 26 6E 62 73 70 3B 3C 61 20 68 72 65 66 3D 5C 22 5C 22 2F 5C 22 26 65 6E 63 6F 64 65 46 6F 72 55 72 6C 28 74 68 65 48 72 65 66 2C 66 61 6C 73 65 29 26 5C 22 5C 22 5C 22 20 74 61 72 67 65 74 3D 5F 62 6C 61 6E 6B 3E 5C 22 26 72 65 70 6C 61 63 65}
		$s9 = {74 68 65 48 72 65 66 3D 6D 69 64 28 72 65 70 6C 61 63 65 28 6C 63 61 73 65 28 6C 69 73 74 2E 70 61 74 68 29 2C 6C 63 61 73 65 28 73 65 72 76 65 72 2E 6D 61 70 50 61 74 68 28 5C 22 2F 5C 22 29 29 2C 5C 22 5C 22 29 2C 32 29}

	condition:
		all of them
}

rule HYTop2006_rar_Folder_2006X2
{
	meta:
		description = "Webshells Auto-generated - file 2006X2.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cc5bf9fc56d404ebbc492855393d7620"

	strings:
		$s2 = {50 6F 77 65 72 65 64 20 42 79 20}
		$s3 = {20 5C 22 20 6F 6E 43 6C 69 63 6B 3D 5C 22 74 68 69 73 2E 66 6F 72 6D 2E 73 68 61 72 70 2E 6E 61 6D 65 3D 74 68 69 73 2E 66 6F 72 6D 2E 70 61 73 73 77 6F 72 64 2E 76 61 6C 75 65 3B 74 68 69 73 2E 66 6F 72 6D 2E 61 63 74 69 6F 6E 3D 74 68 69 73 2E}

	condition:
		all of them
}

rule rdrbs084
{
	meta:
		description = "Webshells Auto-generated - file rdrbs084.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ed30327b255816bdd7590bf891aa0020"

	strings:
		$s0 = {43 72 65 61 74 65 20 6D 61 70 70 65 64 20 70 6F 72 74 2E 20 59 6F 75 20 68 61 76 65 20 74 6F 20 73 70 65 63 69 66 79 20 64 6F 6D 61 69 6E 20 77 68 65 6E 20 75 73 69 6E 67 20 48 54 54 50 20 74 79 70 65 2E}
		$s8 = {3C 4C 4F 43 41 4C 20 50 4F 52 54 3E 20 3C 4D 41 50 50 49 4E 47 20 53 45 52 56 45 52 3E 20 3C 4D 41 50 50 49 4E 47 20 53 45 52 56 45 52 20 50 4F 52 54 3E 20 3C 54 41 52 47 45 54 20 53 45 52 56 45 52 3E 20 3C 54 41 52 47 45 54}

	condition:
		all of them
}

rule HYTop_CaseSwitch_2005
{
	meta:
		description = "Webshells Auto-generated - file 2005.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8bf667ee9e21366bc0bd3491cb614f41"

	strings:
		$s1 = {4D 53 43 6F 6D 44 6C 67 2E 43 6F 6D 6D 6F 6E 44 69 61 6C 6F 67}
		$s2 = {43 6F 6D 6D 6F 6E 44 69 61 6C 6F 67 31}
		$s3 = {5F 5F 76 62 61 45 78 63 65 70 74 48 61 6E 64 6C 65 72}
		$s4 = {45 56 45 4E 54 5F 53 49 4E 4B 5F 52 65 6C 65 61 73 65}
		$s5 = {45 56 45 4E 54 5F 53 49 4E 4B 5F 41 64 64 52 65 66}
		$s6 = {42 79 20 4D 61 72 63 6F 73}
		$s7 = {45 56 45 4E 54 5F 53 49 4E 4B 5F 51 75 65 72 79 49 6E 74 65 72 66 61 63 65}
		$s8 = {4D 65 74 68 43 61 6C 6C 45 6E 67 69 6E 65}

	condition:
		all of them
}

rule eBayId_index3
{
	meta:
		description = "Webshells Auto-generated - file index3.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0412b1e37f41ea0d002e4ed11608905f"

	strings:
		$s8 = {24 65 72 72 20 3D 20 5C 22 3C 69 3E 59 6F 75 72 20 4E 61 6D 65 3C 2F 69 3E 20 4E 6F 74 20 45 6E 74 65 72 65 64 21 3C 2F 66 6F 6E 74 3E 3C 2F 68 32 3E 53 6F 72 72 79 2C 20 5C 5C 5C 22 59 6F 75}

	condition:
		all of them
}

rule FSO_s_phvayv
{
	meta:
		description = "Webshells Auto-generated - file phvayv.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "205ecda66c443083403efb1e5c7f7878"

	strings:
		$s2 = {77 72 61 70 3D 5C 22 4F 46 46 5C 22 3E 58 58 58 58 3C 2F 74 65 78 74 61 72 65 61 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74 20 66 61 63 65}

	condition:
		all of them
}

rule byshell063_ntboot
{
	meta:
		description = "Webshells Auto-generated - file ntboot.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"

	strings:
		$s0 = {53 59 53 54 45 4D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 53 65 72 76 69 63 65 73 5C 5C 4E 74 42 6F 6F 74}
		$s1 = {46 61 69 6C 75 72 65 20 2E 2E 2E 20 41 63 63 65 73 73 20 69 73 20 44 65 6E 69 65 64 20 21}
		$s2 = {44 75 6D 70 69 6E 67 20 44 65 73 63 72 69 70 74 69 6F 6E 20 74 6F 20 52 65 67 69 73 74 72 79 2E 2E 2E}
		$s3 = {4F 70 65 6E 69 6E 67 20 53 65 72 76 69 63 65 20 2E 2E 2E 2E 20 46 61 69 6C 75 72 65 20 21}

	condition:
		all of them
}

rule FSO_s_casus15_2
{
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8d155b4239d922367af5d0a1b89533a3"

	strings:
		$s0 = {63 6F 70 79 20 28 20 24 64 6F 73 79 61 5F 67 6F 6E 64 65 72}

	condition:
		all of them
}

rule installer
{
	meta:
		description = "Webshells Auto-generated - file installer.cmd"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a507919ae701cf7e42fa441d3ad95f8f"

	strings:
		$s0 = {52 65 73 74 6F 72 65 20 4F 6C 64 20 56 61 6E 71 75 69 73 68}
		$s4 = {52 65 49 6E 73 74 61 6C 6C 20 56 61 6E 71 75 69 73 68}

	condition:
		all of them
}

// duplicated
/* rule uploader
{
	meta:
		description = "Webshells Auto-generated - file uploader.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b9a9aab319964351b46bd5fc9d6246a8"

	strings:
		$s0 = {6D 6F 76 65 5F 75 70 6C 6F 61 64 65 64 5F 66 69 6C 65 28 24 75 73 65 72 66 69 6C 65 2C 20 5C 22 65 6E 74 72 69 6B 61 2E 70 68 70 5C 22 29 3B 20}

	condition:
		all of them
}*/

rule FSO_s_remview_2
{
	meta:
		description = "Webshells Auto-generated - file remview.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b4a09911a5b23e00b55abe546ded691c"

	strings:
		$s0 = {3C 78 6D 70 3E 24 6F 75 74 3C 2F}
		$s1 = {2E 6D 6D 28 5C 22 45 76 61 6C 20 50 48 50 20 63 6F 64 65 5C 22 29 2E}

	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_r57
{
	meta:
		description = "Webshells Auto-generated - file r57.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "903908b77a266b855262cdbce81c3f72"

	strings:
		$s1 = {24 73 71 6C 20 3D 20 5C 22 4C 4F 41 44 20 44 41 54 41 20 49 4E 46 49 4C 45 20 5C 5C 5C 22 5C 22 2E 24 5F 50 4F 53 54 5B 27 74 65 73 74 33 5F 66 69 6C 65 27 5D 2E}

	condition:
		all of them
}

rule HYTop2006_rar_Folder_2006X
{
	meta:
		description = "Webshells Auto-generated - file 2006X.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cf3ee0d869dd36e775dfcaa788db8e4b"

	strings:
		$s1 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 70 61 73 73 77 6F 72 64 5C 22 20 74 79 70 65 3D 5C 22 70 61 73 73 77 6F 72 64 5C 22 20 69 64 3D 5C 22 70 61 73 73 77 6F 72 64 5C 22}
		$s6 = {6E 61 6D 65 3D 5C 22 74 68 65 41 63 74 69 6F 6E 5C 22 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 69 64 3D 5C 22 74 68 65 41 63 74 69 6F 6E 5C 22}

	condition:
		all of them
}

rule FSO_s_phvayv_2
{
	meta:
		description = "Webshells Auto-generated - file phvayv.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "205ecda66c443083403efb1e5c7f7878"

	strings:
		$s2 = {72 6F 77 73 3D 5C 22 32 34 5C 22 20 63 6F 6C 73 3D 5C 22 31 32 32 5C 22 20 77 72 61 70 3D 5C 22 4F 46 46 5C 22 3E 58 58 58 58 3C 2F 74 65 78 74 61 72 65 61 3E 3C 2F 66 6F 6E 74 3E 3C 66 6F 6E 74}

	condition:
		all of them
}

rule elmaliseker
{
	meta:
		description = "Webshells Auto-generated - file elmaliseker.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ccf48af0c8c09bbd038e610a49c9862e"

	strings:
		$s0 = {6A 61 76 61 73 63 72 69 70 74 3A 43 6F 6D 6D 61 6E 64 28 27 44 6F 77 6E 6C 6F 61 64 27}
		$s5 = {7A 6F 6D 62 69 65 5F 61 72 72 61 79 3D 61 72 72 61 79 28}

	condition:
		all of them
}

rule shelltools_g0t_root_resolve
{
	meta:
		description = "Webshells Auto-generated - file resolve.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "69bf9aa296238610a0e05f99b5540297"

	strings:
		$s0 = {33 5E 6E 36 42 28 45 64 33}
		$s1 = {5E 75 6C 64 6E 27 56 74 28 78}
		$s2 = {5C 5C 3D 20 75 50 4B 66 70}
		$s3 = {27 72 2E 61 78 56 3C 61 64}
		$s4 = {70 2C 6D 6F 64 6F 69 24 3D 73 72 28}
		$s5 = {44 69 61 6D 6F 6E 64 43 38 53 20 74}
		$s6 = {60 6C 51 39 66 58 3C 5A 76 4A 57}

	condition:
		all of them
}

rule FSO_s_RemExp
{
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b69670ecdbb40012c73686cd22696eeb"

	strings:
		$s1 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 74 69 74 6C 65 3D 5C 22 3C 25 3D 53 75 62 46 6F 6C 64 65 72 2E 4E 61 6D 65 25 3E 5C 22 3E 20 3C 61 20 68 72 65 66 3D 20 5C 22 3C 25 3D 52 65 71 75 65 73 74 2E 53 65 72}
		$s5 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 74 69 74 6C 65 3D 5C 22 3C 25 3D 46 69 6C 65 2E 4E 61 6D 65 25 3E 5C 22 3E 20 3C 61 20 68 72 65 66 3D 20 5C 22 73 68 6F 77 63 6F 64 65 2E 61 73 70 3F 66 3D 3C 25 3D 46}
		$s6 = {3C 74 64 20 62 67 63 6F 6C 6F 72 3D 5C 22 3C 25 3D 42 67 43 6F 6C 6F 72 25 3E 5C 22 20 61 6C 69 67 6E 3D 5C 22 72 69 67 68 74 5C 22 3E 3C 25 3D 41 74 74 72 69 62 75 74 65 73 28 53 75 62 46 6F 6C 64 65 72 2E 41 74 74 72 69 62 75 74 65 73 29 25 3E 3C 2F}

	condition:
		all of them
}

rule FSO_s_tool
{
	meta:
		description = "Webshells Auto-generated - file tool.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3a1e1e889fdd974a130a6a767b42655b"

	strings:
		$s7 = {5C 22 5C 22 25 77 69 6E 64 69 72 25 5C 5C 5C 5C 63 61 6C 63 2E 65 78 65 5C 22 5C 22 29}

	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_2005
{
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "97f2552c2fafc0b2eb467ee29cc803c8"

	strings:
		$s0 = {77 69 6E 64 6F 77 2E 6F 70 65 6E 28 5C 22 5C 22 26 75 72 6C 26 5C 22 3F 69 64 3D 65 64 69 74 26 70 61 74 68 3D 5C 22 2B 73 66 69 6C 65 2B 5C 22 26 6F 70 3D 63 6F 70 79 26 61 74 74 72 69 62 3D 5C 22 2B 61 74 74 72 69 62 2B 5C 22 26 64 70 61 74 68 3D 5C 22 2B 6C 70}
		$s3 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 64 62 6E 61 6D 65 5C 22 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 69 64 3D 5C 22 64 62 6E 61 6D 65 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 72 65 71 75 65 73 74 28 5C 22 64 62 6E 61 6D 65 5C 22 29 25 3E 5C 22 3E}

	condition:
		all of them
}

rule byloader
{
	meta:
		description = "Webshells Auto-generated - file byloader.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0f0d6dc26055653f5844ded906ce52df"

	strings:
		$s0 = {53 59 53 54 45 4D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 53 65 72 76 69 63 65 73 5C 5C 4E 74 66 73 43 68 6B}
		$s1 = {46 61 69 6C 75 72 65 20 2E 2E 2E 20 41 63 63 65 73 73 20 69 73 20 44 65 6E 69 65 64 20 21}
		$s2 = {4E 54 46 53 20 44 69 73 6B 20 44 72 69 76 65 72 20 43 68 65 63 6B 69 6E 67 20 53 65 72 76 69 63 65}
		$s3 = {44 75 6D 70 69 6E 67 20 44 65 73 63 72 69 70 74 69 6F 6E 20 74 6F 20 52 65 67 69 73 74 72 79 2E 2E 2E}
		$s4 = {4F 70 65 6E 69 6E 67 20 53 65 72 76 69 63 65 20 2E 2E 2E 2E 20 46 61 69 6C 75 72 65 20 21}

	condition:
		all of them
}

rule shelltools_g0t_root_Fport
{
	meta:
		description = "Webshells Auto-generated - file Fport.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "dbb75488aa2fa22ba6950aead1ef30d5"

	strings:
		$s4 = {43 6F 70 79 72 69 67 68 74 20 32 30 30 30 20 62 79 20 46 6F 75 6E 64 73 74 6F 6E 65 2C 20 49 6E 63 2E}
		$s5 = {59 6F 75 20 6D 75 73 74 20 68 61 76 65 20 61 64 6D 69 6E 69 73 74 72 61 74 6F 72 20 70 72 69 76 69 6C 65 67 65 73 20 74 6F 20 72 75 6E 20 66 70 6F 72 74 20 2D 20 65 78 69 74 69 6E 67 2E 2E 2E}

	condition:
		all of them
}

rule BackDooR__fr_
{
	meta:
		description = "Webshells Auto-generated - file BackDooR (fr).php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a79cac2cf86e073a832aaf29a664f4be"

	strings:
		$s3 = {70 72 69 6E 74 28 5C 22 3C 70 20 61 6C 69 67 6E 3D 5C 5C 5C 22 63 65 6E 74 65 72 5C 5C 5C 22 3E 3C 66 6F 6E 74 20 73 69 7A 65 3D 5C 5C 5C 22 35 5C 5C 5C 22 3E 45 78 70 6C 6F 69 74 20 69 6E 63 6C 75 64 65 20}

	condition:
		all of them
}

rule FSO_s_ntdaddy
{
	meta:
		description = "Webshells Auto-generated - file ntdaddy.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"

	strings:
		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 2E 43 4D 44 5C 22 20 73 69 7A 65 3D 5C 22 34 35 5C 22 20 76 61 6C 75 65 3D 5C 22 3C 25 3D 20 73 7A 43 4D 44 20 25 3E 5C 22 3E 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 73}

	condition:
		all of them
}

rule nstview_nstview
{
	meta:
		description = "Webshells Auto-generated - file nstview.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3871888a0c1ac4270104918231029a56"

	strings:
		$s4 = {6F 70 65 6E 20 53 54 44 49 4E 2C 5C 5C 5C 22 3C 26 58 5C 5C 5C 22 3B 6F 70 65 6E 20 53 54 44 4F 55 54 2C 5C 5C 5C 22 3E 26 58 5C 5C 5C 22 3B 6F 70 65 6E 20 53 54 44 45 52 52 2C 5C 5C 5C 22 3E 26 58 5C 5C 5C 22 3B 65 78 65 63 28 5C 5C 5C 22 2F 62 69 6E 2F 73 68 20 2D 69 5C 5C 5C 22 29 3B}

	condition:
		all of them
}

rule HYTop_DevPack_upload
{
	meta:
		description = "Webshells Auto-generated - file upload.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b09852bda534627949f0259828c967de"

	strings:
		$s0 = {3C 21 2D 2D 20 50 61 67 65 55 70 6C 6F 61 64 20 42 65 6C 6F 77 20 2D 2D 3E}

	condition:
		all of them
}

rule PasswordReminder
{
	meta:
		description = "Webshells Auto-generated - file PasswordReminder.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ea49d754dc609e8bfa4c0f95d14ef9bf"

	strings:
		$s3 = {54 68 65 20 65 6E 63 6F 64 65 64 20 70 61 73 73 77 6F 72 64 20 69 73 20 66 6F 75 6E 64 20 61 74 20 30 78 25 38 2E 38 6C 78 20 61 6E 64 20 68 61 73 20 61 20 6C 65 6E 67 74 68 20 6F 66 20 25 64 2E}

	condition:
		all of them
}

rule Pack_InjectT
{
	meta:
		description = "Webshells Auto-generated - file InjectT.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "983b74ccd57f6195a0584cdfb27d55e8"

	strings:
		$s3 = {61 69 6C 20 54 6F 20 4F 70 65 6E 20 52 65 67 69 73 74 72 79}
		$s4 = {33 32 66 44 73 73 69 67 6E 69 6D}
		$s5 = {76 69 64 65 20 49 6E 74 65 72 6E 65 74 20 53}
		$s6 = {64 5D 53 6F 66 74 77 61 72 65 5C 5C 4D}
		$s7 = {54 49 6E 6A 65 63 74 2E 44 6C 6C}

	condition:
		all of them
}

rule FSO_s_RemExp_2
{
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b69670ecdbb40012c73686cd22696eeb"

	strings:
		$s2 = {20 54 68 65 6E 20 52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 20 5C 22}
		$s3 = {3C 61 20 68 72 65 66 3D 20 5C 22 3C 25 3D 52 65 71 75 65 73 74 2E 53 65 72 76 65 72 56 61 72 69 61 62 6C 65 73 28 5C 22 73 63 72 69 70 74 5F 6E 61 6D 65 5C 22 29 25 3E}

	condition:
		all of them
}

rule FSO_s_c99
{
	meta:
		description = "Webshells Auto-generated - file c99.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5f9ba02eb081bba2b2434c603af454d0"

	strings:
		$s2 = {5C 22 74 78 74 5C 22 2C 5C 22 63 6F 6E 66 5C 22 2C 5C 22 62 61 74 5C 22 2C 5C 22 73 68 5C 22 2C 5C 22 6A 73 5C 22 2C 5C 22 62 61 6B 5C 22 2C 5C 22 64 6F 63 5C 22 2C 5C 22 6C 6F 67 5C 22 2C 5C 22 73 66 63 5C 22 2C 5C 22 63 66 67 5C 22 2C 5C 22 68 74 61 63 63 65}

	condition:
		all of them
}

rule rknt_zip_Folder_RkNT
{
	meta:
		description = "Webshells Auto-generated - file RkNT.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5f97386dfde148942b7584aeb6512b85"

	strings:
		$s0 = {50 61 74 68 53 74 72 69 70 50 61 74 68 41}
		$s1 = {60 63 4C 47 65 74 21 41 64 64 72 25}
		$s2 = {24 49 6E 66 6F 3A 20 54 68 69 73 20 66 69 6C 65 20 69 73 20 70 61 63 6B 65 64 20 77 69 74 68 20 74 68 65 20 55 50 58 20 65 78 65 63 75 74 61 62 6C 65 20 70 61 63 6B 65 72 20 68 74 74 70 3A 2F 2F 75 70 78 2E 74 73 78 2E 6F 72 67 20 24}
		$s3 = {6F 51 54 6F 4F 65 6D 42 75 66 66 2A 20 3C 3D}
		$s4 = {69 6F 6E 43 64 75 6E 41 73 77 5B 55 73 27}
		$s6 = {43 72 65 61 74 65 50 72 6F 63 65 73 73 57 3A 20 25 53}
		$s7 = {49 6D 61 67 65 44 69 72 65 63 74 6F 72 79 45 6E 74 72 79 54 6F 44 61 74 61}

	condition:
		all of them
}

rule dbgntboot
{
	meta:
		description = "Webshells Auto-generated - file dbgntboot.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "4d87543d4d7f73c1529c9f8066b475ab"

	strings:
		$s2 = {6E 6F 77 20 44 4F 53 20 69 73 20 77 6F 72 6B 69 6E 67 20 61 74 20 6D 6F 64 65 20 25 64 2C 66 61 6B 65 74 79 70 65 20 25 64 2C 61 67 61 69 6E 73 74 20 25 73 2C 68 61 73 20 77 6F 72 6B 65 64 20 25 64 20 6D 69 6E 75 74 65 73 2C 62 79 20 73 70}
		$s3 = {73 74 68 20 6A 75 6E 6B 20 74 68 65 20 4D 24 20 57 69 6E 64 30 77 5A 20 72 65 74 75 72}

	condition:
		all of them
}

rule PHP_shell
{
	meta:
		description = "Webshells Auto-generated - file shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "45e8a00567f8a34ab1cccc86b4bc74b9"

	strings:
		$s0 = {41 52 38 69 52 4F 45 54 36 6D 4D 6E 72 71 54 70 43 36 57 31 4B 70 2F 44 73 54 67 78 4E 62 79 39 48 31 78 68 69 73 77 66 77 67 6F 41 74 45 44 30 79 36 77 45 58 54 69 68 6F 41 74 49 43 6B 49 58 36 4C 31 2B 76 54 55 59 57 75 57 7A}
		$s11 = {31 48 4C 70 31 71 6E 6C 43 79 6C 35 67 6B 6F 38 72 44 6C 57 48 71 66 38 2F 4A 6F 50 4B 76 47 77 45 6D 39 51 34 6E 56 4B 76 45 68 30 62 30 50 4B 6C 65 33 7A 65 46 69 4A 4E 79 6A 78 4F 69 56 65 70 4D 53 70 66 6C 4A 6B 50 76 35 73}

	condition:
		all of them
}

rule hxdef100
{
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "55cc1769cef44910bd91b7b73dee1f6c"

	strings:
		$s0 = {52 74 6C 41 6E 73 69 53 74 72 69 6E 67 54 6F 55 6E 69 63 6F 64 65 53 74 72 69 6E 67}
		$s8 = {53 59 53 54 45 4D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 43 6F 6E 74 72 6F 6C 5C 5C 53 61 66 65 42 6F 6F 74 5C 5C}
		$s9 = {5C 5C 5C 5C 2E 5C 5C 6D 61 69 6C 73 6C 6F 74 5C 5C 68 78 64 65 66 2D 72 6B 31 30 30 73 41 42 43 44 45 46 47 48}

	condition:
		all of them
}

rule rdrbs100
{
	meta:
		description = "Webshells Auto-generated - file rdrbs100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7c752bcd6da796d80a6830c61a632bff"

	strings:
		$s3 = {53 65 72 76 65 72 20 61 64 64 72 65 73 73 20 6D 75 73 74 20 62 65 20 49 50 20 69 6E 20 41 2E 42 2E 43 2E 44 20 66 6F 72 6D 61 74 2E}
		$s4 = {20 6D 61 70 70 65 64 20 70 6F 72 74 73 20 69 6E 20 74 68 65 20 6C 69 73 74 2E 20 43 75 72 72 65 6E 74 6C 79 20}

	condition:
		all of them
}

rule Mithril_Mithril
{
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "017191562d72ab0ca551eb89256650bd"

	strings:
		$s0 = {4F 70 65 6E 50 72 6F 63 65 73 73 20 65 72 72 6F 72 21}
		$s1 = {57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 20 65 72 72 6F 72 21}
		$s4 = {47 65 74 50 72 6F 63 41 64 64 72 65 73 73 20 65 72 72 6F 72 21}
		$s5 = {48 48 74 60 48 48 74 5C 5C}
		$s6 = {43 6D 61 75 64 69 30}
		$s7 = {43 72 65 61 74 65 52 65 6D 6F 74 65 54 68 72 65 61 64 20 65 72 72 6F 72 21}
		$s8 = {4B 65 72 6E 65 6C 33 32}
		$s9 = {56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 20 65 72 72 6F 72 21}

	condition:
		all of them
}

rule hxdef100_2
{
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b393e2e13b9c57fb501b7cd7ad96b25"

	strings:
		$s0 = {5C 5C 5C 5C 2E 5C 5C 6D 61 69 6C 73 6C 6F 74 5C 5C 68 78 64 65 66 2D 72 6B 63 30 30 30}
		$s2 = {53 68 61 72 65 64 20 43 6F 6D 70 6F 6E 65 6E 74 73 5C 5C 4F 6E 20 41 63 63 65 73 73 20 53 63 61 6E 6E 65 72 5C 5C 42 65 68 61 76 69 6F 75 72 42 6C 6F}
		$s6 = {53 59 53 54 45 4D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 43 6F 6E 74 72 6F 6C 5C 5C 53 61 66 65 42 6F 6F 74 5C 5C}

	condition:
		all of them
}

rule Release_dllTest
{
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "76a59fc3242a2819307bb9d593bef2e0"

	strings:
		$s0 = {3B 3B 3B 59 3B 60 3B 64 3B 68 3B 6C 3B 70 3B 74 3B 78 3B 7C 3B}
		$s1 = {30 20 30 26 30 30 30 36 30 4B 30 52 30 58 30 66 30 6C 30 71 30 77 30}
		$s2 = {3A 20 3A 24 3A 28 3A 2C 3A 30 3A 34 3A 38 3A 44 3A 60 3D 64 3D}
		$s3 = {34 40 35 50 35 54 35 5C 5C 35 54 37 5C 5C 37 64 37 6C 37 74 37 7C 37}
		$s4 = {31 2C 31 32 31 3E 31 43 31 4B 31 51 31 58 31 5E 31 65 31 6B 31 73 31 79 31}
		$s5 = {39 20 39 24 39 28 39 2C 39 50 39 58 39 5C 5C 39 60 39 64 39 68 39 6C 39 70 39 74 39 78 39 7C 39}
		$s6 = {30 29 30 4F 30 5C 5C 30 61 30 6F 30 5C 22 31 45 31 50 31 71 31}
		$s7 = {3C 2E 3C 49 3C 64 3C 68 3C 6C 3C 70 3C 74 3C 78 3C 7C 3C}
		$s8 = {33 26 33 31 33 38 33 3E 33 46 33 51 33 58 33 60 33 66 33 77 33 7C 33}
		$s9 = {38 40 3B 44 3B 48 3B 4C 3B 50 3B 54 3B 58 3B 5C 5C 3B 61 3B 39 3D 57 3D 7A 3D}

	condition:
		all of them
}

rule webadmin
{
	meta:
		description = "Webshells Auto-generated - file webadmin.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3a90de401b30e5b590362ba2dde30937"

	strings:
		$s0 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 5C 5C 22 65 64 69 74 66 69 6C 65 6E 61 6D 65 5C 5C 5C 22 20 74 79 70 65 3D 5C 5C 5C 22 74 65 78 74 5C 5C 5C 22 20 63 6C 61 73 73 3D 5C 5C 5C 22 73 74 79 6C 65 31 5C 5C 5C 22 20 76 61 6C 75 65 3D 27 5C 22 2E 24 74 68 69 73 2D 3E 69 6E 70 75}

	condition:
		all of them
}

rule commands
{
	meta:
		description = "Webshells Auto-generated - file commands.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "174486fe844cb388e2ae3494ac2d1ec2"

	strings:
		$s1 = {49 66 20 43 68 65 63 6B 52 65 63 6F 72 64 28 5C 22 53 45 4C 45 43 54 20 43 4F 55 4E 54 28 49 44 29 20 46 52 4F 4D 20 56 69 63 74 69 6D 44 65 74 61 69 6C 20 57 48 45 52 45 20 56 69 63 74 69 6D 49 44 20 3D 20 5C 22 20 26 20 56 69 63 74 69 6D 49 44}
		$s2 = {70 72 6F 78 79 41 72 72 20 3D 20 41 72 72 61 79 20 28 5C 22 48 54 54 50 5F 58 5F 46 4F 52 57 41 52 44 45 44 5F 46 4F 52 5C 22 2C 5C 22 48 54 54 50 5F 56 49 41 5C 22 2C 5C 22 48 54 54 50 5F 43 41 43 48 45 5F 43 4F 4E 54 52 4F 4C 5C 22 2C 5C 22 48 54 54 50 5F 46}

	condition:
		all of them
}

rule hkdoordll
{
	meta:
		description = "Webshells Auto-generated - file hkdoordll.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b715c009d47686c0e62d0981efce2552"

	strings:
		$s6 = {43 61 6E 27 74 20 75 6E 69 6E 73 74 61 6C 6C 2C 6D 61 79 62 65 20 74 68 65 20 62 61 63 6B 64 6F 6F 72 20 69 73 20 6E 6F 74 20 69 6E 73 74 61 6C 6C 65 64 20 6F 72 2C 74 68 65 20 50 61 73 73 77 6F 72 64 20 79 6F 75 20 49 4E 50 55 54 20 69 73}

	condition:
		all of them
}

rule r57shell_2
{
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8023394542cddf8aee5dec6072ed02b5"

	strings:
		$s2 = {65 63 68 6F 20 5C 22 3C 62 72 3E 5C 22 2E 77 73 28 32 29 2E 5C 22 48 44 44 20 46 72 65 65 20 3A 20 3C 62 3E 5C 22 2E 76 69 65 77 5F 73 69 7A 65 28 24 66 72 65 65 29 2E 5C 22 3C 2F 62 3E 20 48 44 44 20 54 6F 74 61 6C 20 3A 20 3C 62 3E 5C 22 2E 76 69 65 77 5F}

	condition:
		all of them
}

rule Mithril_v1_45_dllTest
{
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"

	strings:
		$s3 = {73 79 73 70 61 74 68}
		$s4 = {5C 5C 4D 69 74 68 72 69 6C}
		$s5 = {2D 2D 6C 69 73 74 20 74 68 65 20 73 65 72 76 69 63 65 73 20 69 6E 20 74 68 65 20 63 6F 6D 70 75 74 65 72}

	condition:
		all of them
}

rule dbgiis6cli
{
	meta:
		description = "Webshells Auto-generated - file dbgiis6cli.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3044dceb632b636563f66fee3aaaf8f3"

	strings:
		$s0 = {55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 35 2E 30 31 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 35 2E 30 29}
		$s5 = {23 23 23 63 6F 6D 6D 61 6E 64 3A 28 4E 4F 20 6D 6F 72 65 20 74 68 61 6E 20 31 30 30 20 62 79 74 65 73 21 29}

	condition:
		all of them
}

rule remview_2003_04_22
{
	meta:
		description = "Webshells Auto-generated - file remview_2003_04_22.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "17d3e4e39fbca857344a7650f7ea55e3"

	strings:
		$s1 = {5C 22 3C 62 3E 5C 22 2E 6D 6D 28 5C 22 45 76 61 6C 20 50 48 50 20 63 6F 64 65 5C 22 29 2E 5C 22 3C 2F 62 3E 20 28 5C 22 2E 6D 6D 28 5C 22 64 6F 6E 27 74 20 74 79 70 65 5C 22 29 2E 5C 22 20 5C 5C 5C 22 26 6C 74 3B 3F 5C 5C 5C 22}

	condition:
		all of them
}

rule FSO_s_test
{
	meta:
		description = "Webshells Auto-generated - file test.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "82cf7b48da8286e644f575b039a99c26"

	strings:
		$s0 = {24 79 61 7A 69 20 3D 20 5C 22 74 65 73 74 5C 22 20 2E 20 5C 22 5C 5C 72 5C 5C 6E 5C 22 3B}
		$s2 = {66 77 72 69 74 65 20 28 24 66 70 2C 20 5C 22 24 79 61 7A 69 5C 22 29 3B}

	condition:
		all of them
}

rule Debug_cress
{
	meta:
		description = "Webshells Auto-generated - file cress.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "36a416186fe010574c9be68002a7286a"

	strings:
		$s0 = {5C 5C 4D 69 74 68 72 69 6C 20}
		$s4 = {4D 69 74 68 72 69 6C 2E 65 78 65}

	condition:
		all of them
}

rule webshell
{
	meta:
		description = "Webshells Auto-generated - file webshell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f2f8c02921f29368234bfb4d4622ad19"

	strings:
		$s0 = {52 68 56 69 52 59 4F 7A 7A}
		$s1 = {64 5C 5C 4F 21 6A 57 57}
		$s2 = {62 63 21 6A 57 57}
		$s3 = {30 57 5B 26 7B 6C}
		$s4 = {5B 49 4E 68 51 40 5C 5C}

	condition:
		all of them
}

rule FSO_s_EFSO_2
{
	meta:
		description = "Webshells Auto-generated - file EFSO_2.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a341270f9ebd01320a7490c12cb2e64c"

	strings:
		$s0 = {3B 21 2B 2F 44 52 6B 6E 44 37 2B 2E 5C 5C 6D 44 72 43 28 56 2B 6B 63 4A 7A 6E 6E 64 6D 5C 5C 66 7C 6E 7A 4B 75 4A 62 27 72 40 21 26 30 4B 55 59 40 2A 4A 62 40 23 40 26 58 6C 5C 22 64 4B 56 63 4A 5C 5C 43 73 6C 55 2C 29 2C 40 21 30 4B 78 44 7E 6D 4B 56}
		$s4 = {5C 5C 63 6F 21 56 56 32 43 44 74 53 4A 27 45 2A 23 40 23 40 26 6D 4B 78 2F 44 50 31 34 6C 4D 2F 6E 59 7B 4A 43 38 31 4E 2B 36 4C 74 62 4C 33 5E 68 55 57 61 3B 4D 2F 4F 45 2D 41 58 58 5C 22 62 7E 2F 66 41 73 21 75 26 39 7C 4A 5C 5C 67 72 4B 70 5C 22 6A}

	condition:
		all of them
}

rule thelast_index3
{
	meta:
		description = "Webshells Auto-generated - file index3.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cceff6dc247aaa25512bad22120a14b4"

	strings:
		$s5 = {24 65 72 72 20 3D 20 5C 22 3C 69 3E 59 6F 75 72 20 4E 61 6D 65 3C 2F 69 3E 20 4E 6F 74 20 45 6E 74 65 72 65 64 21 3C 2F 66 6F 6E 74 3E 3C 2F 68 32 3E 53 6F 72 72 79 2C 20 5C 5C 5C 22 59 6F 75 72 20 4E 61 6D 65 5C 5C 5C 22 20 66 69 65 6C 64 20 69 73 20 72}

	condition:
		all of them
}

rule adjustcr
{
	meta:
		description = "Webshells Auto-generated - file adjustcr.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "17037fa684ef4c90a25ec5674dac2eb6"

	strings:
		$s0 = {24 49 6E 66 6F 3A 20 54 68 69 73 20 66 69 6C 65 20 69 73 20 70 61 63 6B 65 64 20 77 69 74 68 20 74 68 65 20 55 50 58 20 65 78 65 63 75 74 61 62 6C 65 20 70 61 63 6B 65 72 20 24}
		$s2 = {24 4C 69 63 65 6E 73 65 3A 20 4E 52 56 20 66 6F 72 20 55 50 58 20 69 73 20 64 69 73 74 72 69 62 75 74 65 64 20 75 6E 64 65 72 20 73 70 65 63 69 61 6C 20 6C 69 63 65 6E 73 65 20 24}
		$s6 = {41 64 6A 75 73 74 43 52 20 43 61 72 72}
		$s7 = {49 4F 4E 5C 5C 53 79 73 74 65 6D 5C 5C 46 6C 6F 61 74 69 6E 67 50 6F}

	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_xIShell
{
	meta:
		description = "Webshells Auto-generated - file xIShell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "997c8437c0621b4b753a546a53a88674"

	strings:
		$s3 = {69 66 20 28 21 24 6E 69 78 29 20 7B 20 24 78 69 64 20 3D 20 69 6D 70 6C 6F 64 65 28 65 78 70 6C 6F 64 65 28 5C 22 5C 5C 5C 5C 5C 22 2C 24 78 69 64 29 2C 5C 22 5C 5C 5C 5C 5C 5C 5C 5C 5C 22 29 3B 7D 65 63 68 6F 20 28 5C 22 3C 74 64 3E 3C 61 20 68 72 65 66 3D 27 4A 61 76 61}

	condition:
		all of them
}

rule HYTop_AppPack_2005
{
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"

	strings:
		$s6 = {5C 22 20 6F 6E 63 6C 69 63 6B 3D 5C 22 74 68 69 73 2E 66 6F 72 6D 2E 73 71 6C 53 74 72 2E 76 61 6C 75 65 3D 27 65 3A 5C 5C 68 79 74 6F 70 2E 6D 64 62}

	condition:
		all of them
}

rule xssshell
{
	meta:
		description = "Webshells Auto-generated - file xssshell.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"

	strings:
		$s1 = {69 66 28 20 21 67 65 74 52 65 71 75 65 73 74 28 43 4F 4D 4D 41 4E 44 53 5F 55 52 4C 20 2B 20 5C 22 3F 76 3D 5C 22 20 2B 20 56 49 43 54 49 4D 20 2B 20 5C 22 26 72 3D 5C 22 20 2B 20 67 65 6E 65 72 61 74 65 49 44 28 29 2C 20 5C 22 70 75 73 68 43 6F 6D 6D 61}

	condition:
		all of them
}

rule FeliksPack3___PHP_Shells_usr
{
	meta:
		description = "Webshells Auto-generated - file usr.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ade3357520325af50c9098dc8a21a024"

	strings:
		$s0 = {3C 3F 70 68 70 20 24 69 64 5F 69 6E 66 6F 20 3D 20 61 72 72 61 79 28 27 6E 6F 74 69 66 79 27 20 3D 3E 20 27 6F 66 66 27 2C 27 73 75 62 27 20 3D 3E 20 27 61 61 73 64 27 2C 27 73 5F 6E 61 6D 65 27 20 3D 3E 20 27 6E 75 72 75 6C 6C 61 68 6F 72}

	condition:
		all of them
}

rule FSO_s_phpinj
{
	meta:
		description = "Webshells Auto-generated - file phpinj.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "dd39d17e9baca0363cc1c3664e608929"

	strings:
		$s4 = {65 63 68 6F 20 27 3C 61 20 68 72 65 66 3D 27 2E 24 65 78 70 75 72 6C 2E 27 3E 20 43 6C 69 63 6B 20 48 65 72 65 20 74 6F 20 45 78 70 6C 6F 69 74 20 3C 2F 61 3E 20 3C 62 72 20 2F 3E 27 3B}

	condition:
		all of them
}

rule xssshell_db
{
	meta:
		description = "Webshells Auto-generated - file db.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cb62e2ec40addd4b9930a9e270f5b318"

	strings:
		$s8 = {27 2F 2F 20 42 79 20 46 65 72 72 75 68 20 4D 61 76 69 74 75 6E 61 20 7C 20 68 74 74 70 3A 2F 2F 66 65 72 72 75 68 2E 6D 61 76 69 74 75 6E 61 2E 63 6F 6D}

	condition:
		all of them
}

rule PHP_sh
{
	meta:
		description = "Webshells Auto-generated - file sh.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1e9e879d49eb0634871e9b36f99fe528"

	strings:
		$s1 = {5C 22 40 24 53 45 52 56 45 52 5F 4E 41 4D 45 20 5C 22 2E 65 78 65 63 28 5C 22 70 77 64 5C 22 29}

	condition:
		all of them
}

rule xssshell_default
{
	meta:
		description = "Webshells Auto-generated - file default.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d156782ae5e0b3724de3227b42fcaf2f"

	strings:
		$s3 = {49 66 20 50 72 6F 78 79 44 61 74 61 20 3C 3E 20 5C 22 5C 22 20 54 68 65 6E 20 50 72 6F 78 79 44 61 74 61 20 3D 20 52 65 70 6C 61 63 65 28 50 72 6F 78 79 44 61 74 61 2C 20 44 41 54 41 5F 53 45 50 45 52 41 54 4F 52 2C 20 5C 22 3C 62 72 20 2F 3E 5C 22 29}

	condition:
		all of them
}

rule EditServer_Webshell_2
{
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"

	strings:
		$s0 = {40 48 4F 54 4D 41 49 4C 2E 43 4F 4D}
		$s1 = {50 72 65 73 73 20 41 6E 79 20 4B 65}
		$s3 = {67 6C 69 73 68 20 4D 65 6E 75 5A}

	condition:
		all of them
}

rule by064cli
{
	meta:
		description = "Webshells Auto-generated - file by064cli.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "10e0dff366968b770ae929505d2a9885"

	strings:
		$s7 = {70 61 63 6B 65 74 20 64 72 6F 70 70 65 64 2C 72 65 64 69 72 65 63 74 69 6E 67}
		$s9 = {69 6E 70 75 74 20 74 68 65 20 70 61 73 73 77 6F 72 64 28 74 68 65 20 64 65 66 61 75 6C 74 20 6F 6E 65 20 69 73 20 27 62 79 27 29}

	condition:
		all of them
}

rule Mithril_dllTest
{
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"

	strings:
		$s0 = {70 6C 65 61 73 65 20 65 6E 74 65 72 20 74 68 65 20 70 61 73 73 77 6F 72 64 3A}
		$s3 = {5C 5C 64 6C 6C 54 65 73 74 2E 70 64 62}

	condition:
		all of them
}

rule peek_a_boo
{
	meta:
		description = "Webshells Auto-generated - file peek-a-boo.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "aca339f60d41fdcba83773be5d646776"

	strings:
		$s0 = {5F 5F 76 62 61 48 72 65 73 75 6C 74 43 68 65 63 6B 4F 62 6A}
		$s1 = {5C 5C 56 42 5C 5C 56 42 35 2E 4F 4C 42}
		$s2 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6F 6E 41}
		$s3 = {5F 5F 76 62 61 45 78 63 65 70 74 48 61 6E 64 6C 65 72}
		$s4 = {45 56 45 4E 54 5F 53 49 4E 4B 5F 52 65 6C 65 61 73 65}
		$s8 = {5F 5F 76 62 61 45 72 72 6F 72 4F 76 65 72 66 6C 6F 77}

	condition:
		all of them
}

rule fmlibraryv3
{
	meta:
		description = "Webshells Auto-generated - file fmlibraryv3.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c34c248fed6d5a20d8203924a2088acc"

	strings:
		$s3 = {45 78 65 4E 65 77 52 73 2E 43 6F 6D 6D 61 6E 64 54 65 78 74 20 3D 20 5C 22 55 50 44 41 54 45 20 5C 22 20 26 20 74 61 62 6C 65 6E 61 6D 65 20 26 20 5C 22 20 53 45 54 20 5C 22 20 26 20 45 78 65 4E 65 77 52 73 56 61 6C 75 65 73 20 26 20 5C 22 20 57 48 45 52}

	condition:
		all of them
}

rule Debug_dllTest_2
{
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"

	strings:
		$s4 = {5C 5C 44 65 62 75 67 5C 5C 64 6C 6C 54 65 73 74 2E 70 64 62}
		$s5 = {2D 2D 6C 69 73 74 20 74 68 65 20 73 65 72 76 69 63 65 73 20 69 6E 20 74 68 65 20 63 6F 6D 70 75 74 65 72}

	condition:
		all of them
}

rule connector
{
	meta:
		description = "Webshells Auto-generated - file connector.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3ba1827fca7be37c8296cd60be9dc884"

	strings:
		$s2 = {49 66 20 28 20 41 74 74 61 63 6B 49 44 20 3D 20 42 52 4F 41 44 43 41 53 54 5F 41 54 54 41 43 4B 20 29}
		$s4 = {41 64 64 20 55 4E 49 51 55 45 20 49 44 20 66 6F 72 20 76 69 63 74 69 6D 73 20 2F 20 7A 6F 6D 62 69 65 73}

	condition:
		all of them
}

rule shelltools_g0t_root_HideRun
{
	meta:
		description = "Webshells Auto-generated - file HideRun.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "45436d9bfd8ff94b71eeaeb280025afe"

	strings:
		$s0 = {55 73 61 67 65 20 2D 2D 20 68 69 64 65 72 75 6E 20 5B 41 70 70 4E 61 6D 65 5D}
		$s7 = {50 56 41 58 20 53 57 2C 20 41 6C 65 78 65 79 20 41 2E 20 50 6F 70 6F 66 66 2C 20 4D 6F 73 63 6F 77 2C 20 31 39 39 37 2E}

	condition:
		all of them
}

rule regshell
{
	meta:
		description = "Webshells Auto-generated - file regshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "db2fdc821ca6091bab3ebd0d8bc46ded"

	strings:
		$s0 = {43 68 61 6E 67 65 73 20 74 68 65 20 62 61 73 65 20 68 69 76 65 20 74 6F 20 48 4B 45 59 5F 43 55 52 52 45 4E 54 5F 55 53 45 52 2E}
		$s4 = {44 69 73 70 6C 61 79 73 20 61 20 6C 69 73 74 20 6F 66 20 76 61 6C 75 65 73 20 61 6E 64 20 73 75 62 2D 6B 65 79 73 20 69 6E 20 61 20 72 65 67 69 73 74 72 79 20 48 69 76 65 2E}
		$s5 = {45 6E 74 65 72 20 61 20 6D 65 6E 75 20 73 65 6C 65 63 74 69 6F 6E 20 6E 75 6D 62 65 72 20 28 31 20 2D 20 33 29 20 6F 72 20 39 39 20 74 6F 20 45 78 69 74 3A 20}

	condition:
		all of them
}

rule PHP_Shell_v1_7
{
	meta:
		description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b5978501c7112584532b4ca6fb77cba5"

	strings:
		$s8 = {3C 74 69 74 6C 65 3E 5B 41 44 44 49 54 49 4E 41 4C 20 54 49 54 54 4C 45 5D 2D 70 68 70 53 68 65 6C 6C 20 62 79 3A 5B 59 4F 55 52 4E 41 4D 45 5D}

	condition:
		all of them
}

rule xssshell_save
{
	meta:
		description = "Webshells Auto-generated - file save.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "865da1b3974e940936fe38e8e1964980"

	strings:
		$s4 = {52 61 77 43 6F 6D 6D 61 6E 64 20 3D 20 43 6F 6D 6D 61 6E 64 20 26 20 43 4F 4D 4D 41 4E 44 5F 53 45 50 45 52 41 54 4F 52 20 26 20 50 61 72 61 6D 20 26 20 43 4F 4D 4D 41 4E 44 5F 53 45 50 45 52 41 54 4F 52 20 26 20 41 74 74 61 63 6B 49 44}
		$s5 = {56 69 63 74 69 6D 49 44 20 3D 20 66 6D 5F 4E 53 74 72 28 56 69 63 74 69 6D 73 28 69 29 29}

	condition:
		all of them
}

rule screencap
{
	meta:
		description = "Webshells Auto-generated - file screencap.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "51139091dea7a9418a50f2712ea72aa6"

	strings:
		$s0 = {47 65 74 44 49 42 43 6F 6C 6F 72 54 61 62 6C 65}
		$s1 = {53 63 72 65 65 6E 2E 62 6D 70}
		$s2 = {43 72 65 61 74 65 44 43 41}

	condition:
		all of them
}

rule FSO_s_phpinj_2
{
	meta:
		description = "Webshells Auto-generated - file phpinj.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "dd39d17e9baca0363cc1c3664e608929"

	strings:
		$s9 = {3C 3F 20 73 79 73 74 65 6D 28 5C 5C 24 5F 47 45 54 5B 63 70 63 5D 29 3B 65 78 69 74 3B 20 3F 3E 27 20 2C 30 20 2C 30 20 2C 30 20 2C 30 20 49 4E 54 4F}

	condition:
		all of them
}

rule ZXshell2_0_rar_Folder_zxrecv
{
	meta:
		description = "Webshells Auto-generated - file zxrecv.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5d3d12a39f41d51341ef4cb7ce69d30f"

	strings:
		$s0 = {52 79 46 6C 75 73 68 42 75 66 66}
		$s1 = {74 65 54 6F 57 69 64 65 43 68 61 72 5E 46 69 59 50}
		$s2 = {6D 64 65 73 63 2B 38 46 20 44}
		$s3 = {5C 5C 76 6F 6E 37 36 73 74 64}
		$s4 = {35 70 75 72 2B 76 69 72 74 75 6C}
		$s5 = {2D 20 4B 61 62 6C 74 6F 20 69 6F}
		$s6 = {61 63 23 66 7B 6C 6F 77 69 38 61}

	condition:
		all of them
}

rule FSO_s_ajan
{
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "22194f8c44524f80254e1b5aec67b03e"

	strings:
		$s4 = {65 6E 74 72 69 6B 61 2E 77 72 69 74 65 20 5C 22 42 69 6E 61 72 79 53 74 72 65 61 6D 2E 53 61 76 65 54 6F 46 69 6C 65}

	condition:
		all of them
}

rule c99shell
{
	meta:
		description = "Webshells Auto-generated - file c99shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "90b86a9c63e2cd346fe07cea23fbfc56"

	strings:
		$s0 = {3C 62 72 20 2F 3E 49 6E 70 75 74 26 6E 62 73 70 3B 55 52 4C 3A 26 6E 62 73 70 3B 26 6C 74 3B 69 6E 70 75 74 26 6E 62 73 70 3B 6E 61 6D 65 3D 5C 5C 5C 22 75 70 6C 6F 61 64 75 72 6C 5C 5C 5C 22 26 6E 62 73 70 3B 74 79 70 65 3D 5C 5C 5C 22 74 65 78 74 5C 5C 5C 22 26}

	condition:
		all of them
}

rule phpspy_2005_full
{
	meta:
		description = "Webshells Auto-generated - file phpspy_2005_full.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d1c69bb152645438440e6c903bac16b2"

	strings:
		$s7 = {65 63 68 6F 20 5C 22 20 20 3C 74 64 20 61 6C 69 67 6E 3D 5C 5C 5C 22 63 65 6E 74 65 72 5C 5C 5C 22 20 6E 6F 77 72 61 70 20 76 61 6C 69 67 6E 3D 5C 5C 5C 22 74 6F 70 5C 5C 5C 22 3E 3C 61 20 68 72 65 66 3D 5C 5C 5C 22 3F 64 6F 77 6E 66 69 6C 65 3D 5C 22 2E 75 72 6C 65 6E 63 6F}

	condition:
		all of them
}

rule FSO_s_zehir4_2
{
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5b496a61363d304532bcf52ee21f5d55"

	strings:
		$s4 = {5C 22 50 72 6F 67 72 61 6D 20 46 69 6C 65 73 5C 5C 53 65 72 76 2D 75 5C 5C 53 65 72 76}

	condition:
		all of them
}

rule httpdoor
{
	meta:
		description = "Webshells Auto-generated - file httpdoor.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6097ea963455a09474471a9864593dc3"

	strings:
		$s4 = {27 27 27 27 27 27 27 27 27 27 27 27 27 27 27 27 27 27 44 61 4A 4B 48 50 61 6D}
		$s5 = {6F 2C 57 69 64 65 43 68 61 72 52 5D 21 6E 5D}
		$s6 = {48 41 75 74 6F 43 6F 6D 70 6C 65 74 65}
		$s7 = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 5C 22 31 2E 30 5C 22 20 65 6E 63 6F 64 69 6E 67 3D 5C 22 55 54 46 2D 38 5C 22 20 73 74 61 6E 64 61 6C 6F 6E 65 3D 5C 22 79 65 73 5C 22 3F 3E 20 3C 61 73 73 65 6D 62 6C 79 20 78 6D 6C 6E 73 3D 5C 22 75 72 6E 3A 73 63 68}

	condition:
		all of them
}

rule FSO_s_indexer_2
{
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "135fc50f85228691b401848caef3be9e"

	strings:
		$s5 = {3C 74 64 3E 4E 65 72 64 65 6E 20 3A 3C 74 64 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 74 65 78 74 5C 22 20 6E 61 6D 65 3D 5C 22 6E 65 72 64 65 6E 5C 22 20 73 69 7A 65 3D 32 35 20 76 61 6C 75 65 3D 69 6E 64 65 78 2E 68 74 6D 6C 3E 3C 2F 74 64 3E}

	condition:
		all of them
}

rule HYTop_DevPack_2005
{
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"

	strings:
		$s7 = {74 68 65 48 72 65 66 3D 65 6E 63 6F 64 65 46 6F 72 55 72 6C 28 6D 69 64 28 72 65 70 6C 61 63 65 28 6C 63 61 73 65 28 6C 69 73 74 2E 70 61 74 68 29 2C 6C 63 61 73 65 28 73 65 72 76 65 72 2E 6D 61 70 50 61 74 68 28 5C 22 2F 5C 22 29 29 2C 5C 22 5C 22 29}
		$s8 = {73 63 72 6F 6C 6C 62 61 72 2D 64 61 72 6B 73 68 61 64 6F 77 2D 63 6F 6C 6F 72 3A 23 39 43 39 43 44 33 3B}
		$s9 = {73 63 72 6F 6C 6C 62 61 72 2D 66 61 63 65 2D 63 6F 6C 6F 72 3A 23 45 34 45 34 46 33 3B}

	condition:
		all of them
}

rule _root_040_zip_Folder_deploy
{
	meta:
		description = "Webshells Auto-generated - file deploy.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2c9f9c58999256c73a5ebdb10a9be269"

	strings:
		$s5 = {68 61 6C 6F 6E 20 73 79 6E 73 63 61 6E 20 31 32 37 2E 30 2E 30 2E 31 20 31 2D 36 35 35 33 36}
		$s8 = {4F 62 76 69 6F 75 73 6C 79 20 79 6F 75 20 72 65 70 6C 61 63 65 20 74 68 65 20 69 70 20 61 64 64 72 65 73 73 20 77 69 74 68 20 74 68 61 74 20 6F 66 20 74 68 65 20 74 61 72 67 65 74 2E}

	condition:
		all of them
}

rule by063cli
{
	meta:
		description = "Webshells Auto-generated - file by063cli.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "49ce26eb97fd13b6d92a5e5d169db859"

	strings:
		$s2 = {23 70 6F 70 6D 73 67 68 65 6C 6C 6F 2C 61 72 65 20 79 6F 75 20 61 6C 6C 20 72 69 67 68 74 3F}
		$s4 = {63 6F 6E 6E 65 63 74 20 66 61 69 6C 65 64 2C 63 68 65 63 6B 20 79 6F 75 72 20 6E 65 74 77 6F 72 6B 20 61 6E 64 20 72 65 6D 6F 74 65 20 69 70 2E}

	condition:
		all of them
}

rule icyfox007v1_10_rar_Folder_asp
{
	meta:
		description = "Webshells Auto-generated - file asp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2c412400b146b7b98d6e7755f7159bb9"

	strings:
		$s0 = {3C 53 43 52 49 50 54 20 52 55 4E 41 54 3D 53 45 52 56 45 52 20 4C 41 4E 47 55 41 47 45 3D 4A 41 56 41 53 43 52 49 50 54 3E 65 76 61 6C 28 52 65 71 75 65 73 74 2E 66 6F 72 6D 28 27 23 27 29 2B 27 27 29 3C 2F 53 43 52 49 50 54 3E}

	condition:
		all of them
}

// duplicated
/* rule FSO_s_EFSO_2_2
{
	meta:
		description = "Webshells Auto-generated - file EFSO_2.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a341270f9ebd01320a7490c12cb2e64c"

	strings:
		$s0 = {3B 21 2B 2F 44 52 6B 6E 44 37 2B 2E 5C 5C 6D 44 72 43 28 56 2B 6B 63 4A 7A 6E 6E 64 6D 5C 5C 66 7C 6E 7A 4B 75 4A 62 27 72 40 21 26 30 4B 55 59 40 2A 4A 62 40 23 40 26 58 6C 5C 22 64 4B 56 63 4A 5C 5C 43 73 6C 55 2C 29 2C 40 21 30 4B 78 44 7E 6D 4B 56}
		$s4 = {5C 5C 63 6F 21 56 56 32 43 44 74 53 4A 27 45 2A 23 40 23 40 26 6D 4B 78 2F 44 50 31 34 6C 4D 2F 6E 59 7B 4A 43 38 31 4E 2B 36 4C 74 62 4C 33 5E 68 55 57 61 3B 4D 2F 4F 45 2D 41 58 58 5C 22 62 7E 2F 66 41 73 21 75 26 39 7C 4A 5C 5C 67 72 4B 70 5C 22 6A}

	condition:
		all of them
}*/

rule byshell063_ntboot_2
{
	meta:
		description = "Webshells Auto-generated - file ntboot.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"

	strings:
		$s6 = {4F 4B 2C 6A 6F 62 20 77 61 73 20 64 6F 6E 65 2C 63 75 7A 20 77 65 20 68 61 76 65 20 6C 6F 63 61 6C 73 79 73 74 65 6D 20 26 20 53 45 5F 44 45 42 55 47 5F 4E 41 4D 45 3A 29}

	condition:
		all of them
}

rule u_uay
{
	meta:
		description = "Webshells Auto-generated - file uay.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "abbc7b31a24475e4c5d82fc4c2b8c7c4"

	strings:
		$s1 = {65 78 65 63 20 5C 22 63 3A 5C 5C 57 49 4E 44 4F 57 53 5C 5C 53 79 73 74 65 6D 33 32 5C 5C 66 72 65 65 63 65 6C 6C 2E 65 78 65}
		$s9 = {53 59 53 54 45 4D 5C 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 5C 53 65 72 76 69 63 65 73 5C 5C 75 61 79 2E 73 79 73 5C 5C 53 65 63 75 72 69 74 79}

	condition:
		1 of them
}

rule bin_wuaus
{
	meta:
		description = "Webshells Auto-generated - file wuaus.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "46a365992bec7377b48a2263c49e4e7d"

	strings:
		$s1 = {39 28 39 30 39 38 39 40 39 56 39 5E 39 66 39 6E 39 76 39}
		$s2 = {3A 28 3A 2C 3A 30 3A 34 3A 38 3A 43 3A 48 3A 4E 3A 54 3A 59 3A 5F 3A 65 3A 6F 3A 79 3A}
		$s3 = {3B 28 3D 40 3D 47 3D 4F 3D 54 3D 58 3D 5C 5C 3D}
		$s4 = {54 43 50 20 53 65 6E 64 20 45 72 72 6F 72 21 21}
		$s5 = {31 5C 22 31 3B 31 58 31 5E 31 65 31 6D 31 77 31 7E 31}
		$s8 = {3D 24 3D 29 3D 2F 3D 3C 3D 59 3D 5F 3D 6A 3D 70 3D 7A 3D}

	condition:
		all of them
}

rule pwreveal
{
	meta:
		description = "Webshells Auto-generated - file pwreveal.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b4e8447826a45b76ca45ba151a97ad50"

	strings:
		$s0 = {2A 3C 42 6C 61 6E 6B 20 2D 20 6E 6F 20 65 73}
		$s3 = {4A 44 69 61 6D 6F 6E 64 43 53 20}
		$s8 = {73 77 6F 72 64 20 73 65 74 3E 20 5B 4C 65 69 74 68 3D 30 20 62 79 74 65 73 5D}
		$s9 = {49 4F 4E 5C 5C 53 79 73 74 65 6D 5C 5C 46 6C 6F 61 74 69 6E 67 2D}

	condition:
		all of them
}

rule shelltools_g0t_root_xwhois
{
	meta:
		description = "Webshells Auto-generated - file xwhois.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0bc98bd576c80d921a3460f8be8816b4"

	strings:
		$s1 = {72 74 69 6E 67 21 20}
		$s2 = {61 54 79 70 43 6F 67 28}
		$s5 = {44 69 61 6D 6F 6E 64}
		$s6 = {72 29 72 3D 72 51 72 65 72 79 72}

	condition:
		all of them
}

rule vanquish_2
{
	meta:
		description = "Webshells Auto-generated - file vanquish.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2dcb9055785a2ee01567f52b5a62b071"

	strings:
		$s2 = {56 61 6E 71 75 69 73 68 20 2D 20 44 4C 4C 20 69 6E 6A 65 63 74 69 6F 6E 20 66 61 69 6C 65 64 3A}

	condition:
		all of them
}

rule down_rar_Folder_down
{
	meta:
		description = "Webshells Auto-generated - file down.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "db47d7a12b3584a2e340567178886e71"

	strings:
		$s0 = {72 65 73 70 6F 6E 73 65 2E 77 72 69 74 65 20 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 62 6C 75 65 20 73 69 7A 65 3D 32 3E 4E 65 74 42 69 6F 73 20 4E 61 6D 65 3A 20 5C 5C 5C 5C 5C 22 20 20 26 20 53 6E 65 74 2E 43 6F 6D 70 75 74 65 72 4E 61 6D 65 20 26}

	condition:
		all of them
}

rule cmdShell
{
	meta:
		description = "Webshells Auto-generated - file cmdShell.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8a9fef43209b5d2d4b81dfbb45182036"

	strings:
		$s1 = {69 66 20 63 6D 64 50 61 74 68 3D 5C 22 77 73 63 72 69 70 74 53 68 65 6C 6C 5C 22 20 74 68 65 6E}

	condition:
		all of them
}

rule ZXshell2_0_rar_Folder_nc
{
	meta:
		description = "Webshells Auto-generated - file nc.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2cd1bf15ae84c5f6917ddb128827ae8b"

	strings:
		$s0 = {57 53 4F 43 4B 33 32 2E 64 6C 6C}
		$s1 = {3F 62 53 55 4E 4B 4E 4F 57 4E 56}
		$s7 = {70 40 67 72 61 6D 20 4A 6D 36 68 29}
		$s8 = {73 65 72 33 32 2E 64 6C 6C 43 4F 4E 46 50 40}

	condition:
		all of them
}

rule portlessinst
{
	meta:
		description = "Webshells Auto-generated - file portlessinst.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "74213856fc61475443a91cd84e2a6c2f"

	strings:
		$s2 = {46 61 69 6C 20 54 6F 20 4F 70 65 6E 20 52 65 67 69 73 74 72 79}
		$s3 = {66 3C 2D 57 4C 45 67 67 44 72 5C 22}
		$s6 = {6F 4D 65 6D 6F 72 79 43 72 65 61 74 65 50}

	condition:
		all of them
}

rule SetupBDoor
{
	meta:
		description = "Webshells Auto-generated - file SetupBDoor.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "41f89e20398368e742eda4a3b45716b6"

	strings:
		$s1 = {5C 5C 42 44 6F 6F 72 5C 5C 53 65 74 75 70 42 44 6F 6F 72}

	condition:
		all of them
}

rule phpshell_3
{
	meta:
		description = "Webshells Auto-generated - file phpshell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "e8693a2d4a2ffea4df03bb678df3dc6d"

	strings:
		$s3 = {3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 73 75 62 6D 69 74 5F 62 74 6E 5C 22 20 74 79 70 65 3D 5C 22 73 75 62 6D 69 74 5C 22 20 76 61 6C 75 65 3D 5C 22 45 78 65 63 75 74 65 20 43 6F 6D 6D 61 6E 64 5C 22 3E 3C 2F 70 3E}
		$s5 = {20 20 20 20 20 20 65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 24 77 6F 72 6B 5F 64 69 72 5C 5C 5C 22 20 73 65 6C 65 63 74 65 64 3E 43 75 72 72 65 6E 74 20 44 69 72 65 63 74 6F 72 79 3C 2F 6F 70 74 69 6F 6E 3E 5C 5C 6E 5C 22 3B}

	condition:
		all of them
}

rule BIN_Server
{
	meta:
		description = "Webshells Auto-generated - file Server.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1d5aa9cbf1429bb5b8bf600335916dcd"

	strings:
		$s0 = {63 6F 6E 66 69 67 73 65 72 76 65 72}
		$s1 = {47 65 74 4C 6F 67 69 63 61 6C 44 72 69 76 65 73}
		$s2 = {57 69 6E 45 78 65 63}
		$s4 = {66 78 66 74 65 73 74}
		$s5 = {75 70 66 69 6C 65 6F 6B}
		$s7 = {75 70 66 69 6C 65 65 72}

	condition:
		all of them
}

rule HYTop2006_rar_Folder_2006
{
	meta:
		description = "Webshells Auto-generated - file 2006.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c19d6f4e069188f19b08fa94d44bc283"

	strings:
		$s6 = {73 74 72 42 61 63 6B 44 6F 6F 72 20 3D 20 73 74 72 42 61 63 6B 44 6F 6F 72 20}

	condition:
		all of them
}

rule r57shell_3
{
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "87995a49f275b6b75abe2521e03ac2c0"

	strings:
		$s1 = {3C 62 3E 5C 22 2E 24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D}

	condition:
		all of them
}

rule HDConfig
{
	meta:
		description = "Webshells Auto-generated - file HDConfig.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7d60e552fdca57642fd30462416347bd"

	strings:
		$s0 = {41 6E 20 65 6E 63 72 79 70 74 69 6F 6E 20 6B 65 79 20 69 73 20 64 65 72 69 76 65 64 20 66 72 6F 6D 20 74 68 65 20 70 61 73 73 77 6F 72 64 20 68 61 73 68 2E 20}
		$s3 = {41 20 68 61 73 68 20 6F 62 6A 65 63 74 20 68 61 73 20 62 65 65 6E 20 63 72 65 61 74 65 64 2E 20}
		$s4 = {45 72 72 6F 72 20 64 75 72 69 6E 67 20 43 72 79 70 74 43 72 65 61 74 65 48 61 73 68 21}
		$s5 = {41 20 6E 65 77 20 6B 65 79 20 63 6F 6E 74 61 69 6E 65 72 20 68 61 73 20 62 65 65 6E 20 63 72 65 61 74 65 64 2E}
		$s6 = {54 68 65 20 70 61 73 73 77 6F 72 64 20 68 61 73 20 62 65 65 6E 20 61 64 64 65 64 20 74 6F 20 74 68 65 20 68 61 73 68 2E 20}

	condition:
		all of them
}

rule FSO_s_ajan_2
{
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "22194f8c44524f80254e1b5aec67b03e"

	strings:
		$s2 = {5C 22 53 65 74 20 57 73 68 53 68 65 6C 6C 20 3D 20 43 72 65 61 74 65 4F 62 6A 65 63 74 28 5C 22 5C 22 57 53 63 72 69 70 74 2E 53 68 65 6C 6C 5C 22 5C 22 29}
		$s3 = {2F 66 69 6C 65 2E 7A 69 70}

	condition:
		all of them
}

rule Webshell_and_Exploit_CN_APT_HK : Webshell
{
	meta:
		author = "Florian Roth"
		description = "Webshell and Exploit Code in relation with APT against Honk Kong protesters"
		date = "10.10.2014"
		score = 50

	strings:
		$a0 = {3C 73 63 72 69 70 74 20 6C 61 6E 67 75 61 67 65 3D 6A 61 76 61 73 63 72 69 70 74 20 73 72 63 3D 68 74 74 70 3A 2F 2F 6A 61 76 61 2D 73 65 2E 63 6F 6D 2F 6F 2E 6A 73 3C 2F 73 63 72 69 70 74 3E}
		$s0 = {3C 73 70 61 6E 20 73 74 79 6C 65 3D 5C 22 66 6F 6E 74 3A 31 31 70 78 20 56 65 72 64 61 6E 61 3B 5C 22 3E 50 61 73 73 77 6F 72 64 3A 20 3C 2F 73 70 61 6E 3E 3C 69 6E 70 75 74 20 6E 61 6D 65 3D 5C 22 70 61 73 73 77 6F 72 64 5C 22 20 74 79 70 65 3D 5C 22 70 61 73 73 77 6F 72 64 5C 22 20 73 69 7A 65 3D 5C 22 32 30 5C 22 3E}
		$s1 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 64 6F 69 6E 67 5C 22 20 76 61 6C 75 65 3D 5C 22 6C 6F 67 69 6E 5C 22 3E}

	condition:
		$a0 or ( all of ($s*))
}

rule JSP_Browser_APT_webshell
{
	meta:
		description = "VonLoesch JSP Browser used as web shell by APT groups - jsp File browser 1.1a"
		author = "F.Roth"
		date = "10.10.2014"
		score = 60

	strings:
		$a1a = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 66 69 6E 61 6C 20 53 74 72 69 6E 67 5B 5D 20 43 4F 4D 4D 41 4E 44 5F 49 4E 54 45 52 50 52 45 54 45 52 20 3D 20 7B 5C 22}
		$a1b = {63 6D 64 5C 22 2C 20 5C 22 2F 43 5C 22 7D 3B 20 2F 2F 20 44 6F 73 2C 57 69 6E 64 6F 77 73}
		$a2 = {50 72 6F 63 65 73 73 20 6C 73 5F 70 72 6F 63 20 3D 20 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 63 6F 6D 6D 2C 20 6E 75 6C 6C 2C 20 6E 65 77 20 46 69 6C 65 28 64 69 72 29 29 3B}
		$a3 = {72 65 74 2E 61 70 70 65 6E 64 28 5C 22 21 21 21 21 20 50 72 6F 63 65 73 73 20 68 61 73 20 74 69 6D 65 64 20 6F 75 74 2C 20 64 65 73 74 72 6F 79 65 64 20 21 21 21 21 21 5C 22 29 3B}

	condition:
		all of them
}

rule JSP_jfigueiredo_APT_webshell
{
	meta:
		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
		author = "F.Roth"
		date = "12.10.2014"
		score = 60
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"

	strings:
		$a1 = {53 74 72 69 6E 67 20 66 68 69 64 64 65 6E 20 3D 20 6E 65 77 20 53 74 72 69 6E 67 28 42 61 73 65 36 34 2E 65 6E 63 6F 64 65 42 61 73 65 36 34 28 70 61 74 68 2E 67 65 74 42 79 74 65 73 28 29 29 29 3B}
		$a2 = {3C 66 6F 72 6D 20 69 64 3D 5C 22 75 70 6C 6F 61 64 5C 22 20 6E 61 6D 65 3D 5C 22 75 70 6C 6F 61 64 5C 22 20 61 63 74 69 6F 6E 3D 5C 22 53 65 72 76 46 4D 55 70 6C 6F 61 64 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54 5C 22 20 65 6E 63 74 79 70 65 3D 5C 22 6D 75 6C 74 69 70 61 72 74 2F 66 6F 72 6D 2D 64 61 74 61 5C 22 3E}

	condition:
		all of them
}

rule JSP_jfigueiredo_APT_webshell_2
{
	meta:
		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
		author = "F.Roth"
		date = "12.10.2014"
		score = 60
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"

	strings:
		$a1 = {3C 64 69 76 20 69 64 3D 5C 22 62 6B 6F 72 6F 74 61 74 6F 72 5C 22 3E 3C 69 6D 67 20 61 6C 74 3D 5C 22 5C 22 20 73 72 63 3D 5C 22 69 6D 61 67 65 73 2F 72 6F 74 61 74 6F 72 2F 31 2E 6A 70 67 5C 22 3E 3C 2F 64 69 76 3E}
		$a2 = {24 28 5C 22 23 64 69 61 6C 6F 67 5C 22 29 2E 64 69 61 6C 6F 67 28 5C 22 64 65 73 74 72 6F 79 5C 22 29 3B}
		$s1 = {3C 66 6F 72 6D 20 69 64 3D 5C 22 66 6F 72 6D 5C 22 20 61 63 74 69 6F 6E 3D 5C 22 53 65 72 76 46 4D 55 70 6C 6F 61 64 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 70 6F 73 74 5C 22 20 65 6E 63 74 79 70 65 3D 5C 22 6D 75 6C 74 69 70 61 72 74 2F 66 6F 72 6D 2D 64 61 74 61 5C 22 3E}
		$s2 = {3C 69 6E 70 75 74 20 74 79 70 65 3D 5C 22 68 69 64 64 65 6E 5C 22 20 69 64 3D 5C 22 66 68 69 64 64 65 6E 5C 22 20 6E 61 6D 65 3D 5C 22 66 68 69 64 64 65 6E 5C 22 20 76 61 6C 75 65 3D 5C 22 4C 33 42 6B 5A 69 38 3D 5C 22 20 2F 3E}

	condition:
		all of ($a*) or all of ($s*)
}

rule AJAX_FileUpload_webshell
{
	meta:
		description = "AJAX JS/CSS components providing web shell by APT groups"
		author = "F.Roth"
		date = "12.10.2014"
		score = 75
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/ajaxfileupload.js"

	strings:
		$a1 = {76 61 72 20 66 72 61 6D 65 49 64 20 3D 20 27 6A 55 70 6C 6F 61 64 46 72 61 6D 65 27 20 2B 20 69 64 3B}
		$a2 = {76 61 72 20 66 6F 72 6D 20 3D 20 6A 51 75 65 72 79 28 27 3C 66 6F 72 6D 20 20 61 63 74 69 6F 6E 3D 5C 22 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54 5C 22 20 6E 61 6D 65 3D 5C 22 27 20 2B 20 66 6F 72 6D 49 64 20 2B 20 27 5C 22 20 69 64 3D 5C 22 27 20 2B 20 66 6F 72 6D 49 64 20 2B 20 27 5C 22 20 65 6E 63 74 79 70 65 3D 5C 22 6D 75 6C 74 69 70 61 72 74 2F 66 6F 72 6D 2D 64 61 74 61 5C 22 3E 3C 2F 66 6F 72 6D 3E 27 29 3B}
		$a3 = {6A 51 75 65 72 79 28 5C 22 3C 64 69 76 3E 5C 22 29 2E 68 74 6D 6C 28 64 61 74 61 29 2E 65 76 61 6C 53 63 72 69 70 74 73 28 29 3B}

	condition:
		all of them
}

rule Webshell_Insomnia
{
	meta:
		description = "Insomnia Webshell - file InsomniaShell.aspx"
		author = "Florian Roth"
		reference = "http://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/"
		date = "2014/12/09"
		hash = "e0cfb2ffaa1491aeaf7d3b4ee840f72d42919d22"
		score = 80

	strings:
		$s0 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 28 5C 22 2D 20 46 61 69 6C 65 64 20 74 6F 20 63 72 65 61 74 65 20 6E 61 6D 65 64 20 70 69 70 65 3A 5C 22 29 3B}
		$s1 = {52 65 73 70 6F 6E 73 65 2E 4F 75 74 70 75 74 2E 57 72 69 74 65 28 5C 22 2B 20 53 65 6E 64 69 6E 67 20 7B 30 7D 3C 62 72 3E 5C 22 2C 20 63 6F 6D 6D 61 6E 64 29 3B}
		$s2 = {53 74 72 69 6E 67 20 63 6F 6D 6D 61 6E 64 20 3D 20 5C 22 65 78 65 63 20 6D 61 73 74 65 72 2E 2E 78 70 5F 63 6D 64 73 68 65 6C 6C 20 27 64 69 72 20 3E 20 5C 5C 5C 5C 5C 5C 5C 5C 31 32 37 2E 30 2E 30 2E 31}
		$s3 = {52 65 73 70 6F 6E 73 65 2E 57 72 69 74 65 28 5C 22 2D 20 45 72 72 6F 72 20 47 65 74 74 69 6E 67 20 55 73 65 72 20 49 6E 66 6F 3C 62 72 3E 5C 22 29 3B}
		$s4 = {73 74 72 69 6E 67 20 6C 70 43 6F 6D 6D 61 6E 64 4C 69 6E 65 2C 20 72 65 66 20 53 45 43 55 52 49 54 59 5F 41 54 54 52 49 42 55 54 45 53 20 6C 70 50 72 6F 63 65 73 73 41 74 74 72 69 62 75 74 65 73 2C}
		$s5 = {5B 44 6C 6C 49 6D 70 6F 72 74 28 5C 22 41 64 76 61 70 69 33 32 2E 64 6C 6C 5C 22 2C 20 53 65 74 4C 61 73 74 45 72 72 6F 72 20 3D 20 74 72 75 65 29 5D}
		$s9 = {75 73 65 72 6E 61 6D 65 20 3D 20 44 75 6D 70 41 63 63 6F 75 6E 74 53 69 64 28 74 6F 6B 55 73 65 72 2E 55 73 65 72 2E 53 69 64 29 3B}
		$s14 = {2F 2F 52 65 73 70 6F 6E 73 65 2E 4F 75 74 70 75 74 2E 57 72 69 74 65 28 5C 22 4F 70 65 6E 65 64 20 70 72 6F 63 65 73 73 20 50 49 44 3A 20 7B 30 7D 20 3A 20 7B 31 7D 3C 62 72 3E 5C 22 2C 20 70}

	condition:
		3 of them
}

rule HawkEye_PHP_Panel
{
	meta:
		description = "Detects HawkEye Keyloggers PHP Panel"
		author = "Florian Roth"
		date = "2014/12/14"
		score = 60

	strings:
		$s0 = {24 66 6E 61 6D 65 20 3D 20 24 5F 47 45 54 5B 27 66 6E 61 6D 65 27 5D 3B}
		$s1 = {24 64 61 74 61 20 3D 20 24 5F 47 45 54 5B 27 64 61 74 61 27 5D 3B}
		$s2 = {75 6E 6C 69 6E 6B 28 24 66 6E 61 6D 65 29 3B}
		$s3 = {65 63 68 6F 20 5C 22 53 75 63 63 65 73 73 5C 22 3B}

	condition:
		all of ($s*) and filesize <600
}

rule SoakSoak_Infected_Wordpress
{
	meta:
		description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
		reference = "http://goo.gl/1GzWUX"
		author = "Florian Roth"
		date = "2014/12/15"
		score = 60

	strings:
		$s0 = {77 70 5F 65 6E 71 75 65 75 65 5F 73 63 72 69 70 74 28 5C 22 73 77 66 6F 62 6A 65 63 74 5C 22 29 3B}
		$s1 = {66 75 6E 63 74 69 6F 6E 20 46 75 6E 63 51 75 65 75 65 4F 62 6A 65 63 74 28 29}
		$s2 = {61 64 64 5F 61 63 74 69 6F 6E 28 5C 22 77 70 5F 65 6E 71 75 65 75 65 5F 73 63 72 69 70 74 73 5C 22 2C 20 27 46 75 6E 63 51 75 65 75 65 4F 62 6A 65 63 74 27 29 3B}

	condition:
		all of ($s*)
}

rule Pastebin_Webshell
{
	meta:
		description = "Detects a web shell that downloads content from pastebin.com http://goo.gl/7dbyZs"
		author = "Florian Roth"
		score = 70
		date = "13.01.2015"
		reference = "http://goo.gl/7dbyZs"

	strings:
		$s0 = {66 69 6C 65 5F 67 65 74 5F 63 6F 6E 74 65 6E 74 73 28 5C 22 68 74 74 70 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D}
		$s1 = {78 63 75 72 6C 28 27 68 74 74 70 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D 2F 64 6F 77 6E 6C 6F 61 64 2E 70 68 70}
		$s2 = {78 63 75 72 6C 28 27 68 74 74 70 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D 2F 72 61 77 2E 70 68 70}
		$x0 = {69 66 28 24 63 6F 6E 74 65 6E 74 29 7B 75 6E 6C 69 6E 6B 28 27 65 76 65 78 2E 70 68 70 27 29 3B}
		$x1 = {24 66 68 32 20 3D 20 66 6F 70 65 6E 28 5C 22 65 76 65 78 2E 70 68 70 5C 22 2C 20 27 61 27 29 3B}
		$y0 = {66 69 6C 65 5F 70 75 74 5F 63 6F 6E 74 65 6E 74 73 28 24 70 74 68}
		$y1 = {65 63 68 6F 20 5C 22 3C 6C 6F 67 69 6E 5F 6F 6B 3E}
		$y2 = {73 74 72 5F 72 65 70 6C 61 63 65 28 27 2A 20 40 70 61 63 6B 61 67 65 20 57 6F 72 64 70 72 65 73 73 27 2C 24 74 65 6D 70}

	condition:
		1 of ($s*) or all of ($x*) or all of ($y*)
}

rule ASPXspy2
{
	meta:
		description = "Web shell - file ASPXspy2.aspx"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/24"
		hash = "5642387d92139bfe9ae11bfef6bfe0081dcea197"

	strings:
		$s0 = {73 74 72 69 6E 67 20 69 56 44 54 3D 5C 22 2D 53 45 54 55 53 45 52 53 45 54 55 50 5C 5C 72 5C 5C 6E 2D 49 50 3D 30 2E 30 2E 30 2E 30 5C 5C 72 5C 5C 6E 2D 50 6F 72 74 4E 6F 3D 35 32 35 32 31 5C 5C 72 5C 5C 6E 2D 55 73 65 72 3D 62 69 6E}
		$s1 = {53 51 4C 45 78 65 63 20 3A 20 3C 61 73 70 3A 44 72 6F 70 44 6F 77 6E 4C 69 73 74 20 72 75 6E 61 74 3D 5C 22 73 65 72 76 65 72 5C 22 20 49 44 3D 5C 22 46 47 45 79 5C 22 20 41 75 74 6F 50 6F 73 74 42 61 63 6B 3D 5C 22 54 72 75 65 5C 22 20 4F}
		$s3 = {50 72 6F 63 65 73 73 5B 5D 20 70 3D 50 72 6F 63 65 73 73 2E 47 65 74 50 72 6F 63 65 73 73 65 73 28 29 3B}
		$s4 = {52 65 73 70 6F 6E 73 65 2E 43 6F 6F 6B 69 65 73 2E 41 64 64 28 6E 65 77 20 48 74 74 70 43 6F 6F 6B 69 65 28 76 62 68 4C 6E 2C 50 61 73 73 77 6F 72 64 29 29 3B}
		$s5 = {5B 44 6C 6C 49 6D 70 6F 72 74 28 5C 22 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 5C 22 2C 45 6E 74 72 79 50 6F 69 6E 74 3D 5C 22 47 65 74 44 72 69 76 65 54 79 70 65 41 5C 22 29 5D}
		$s6 = {3C 70 3E 43 6F 6E 6E 53 74 72 69 6E 67 20 3A 20 3C 61 73 70 3A 54 65 78 74 42 6F 78 20 69 64 3D 5C 22 4D 61 73 52 5C 22 20 73 74 79 6C 65 3D 5C 22 77 69 64 74 68 3A 37 30 25 3B 6D 61 72 67 69 6E 3A 30 20 38 70 78 3B 5C 22 20 43 73 73 43 6C}
		$s7 = {53 65 72 76 69 63 65 43 6F 6E 74 72 6F 6C 6C 65 72 5B 5D 20 6B 51 6D 52 75 3D 53 79 73 74 65 6D 2E 53 65 72 76 69 63 65 50 72 6F 63 65 73 73 2E 53 65 72 76 69 63 65 43 6F 6E 74 72 6F 6C 6C 65 72 2E 47 65 74 53 65 72 76 69 63 65 73 28 29 3B}
		$s8 = {43 6F 70 79 72 69 67 68 74 20 26 63 6F 70 79 3B 20 32 30 30 39 20 42 69 6E 20 2D 2D 20 3C 61 20 68 72 65 66 3D 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 72 6F 6F 74 6B 69 74 2E 6E 65 74 2E 63 6E 5C 22 20 74 61 72 67 65 74 3D 5C 22 5F 62 6C 61}
		$s10 = {52 65 73 70 6F 6E 73 65 2E 41 64 64 48 65 61 64 65 72 28 5C 22 43 6F 6E 74 65 6E 74 2D 44 69 73 70 6F 73 69 74 69 6F 6E 5C 22 2C 5C 22 61 74 74 61 63 68 6D 65 6E 74 3B 66 69 6C 65 6E 61 6D 65 3D 5C 22 2B 48 74 74 70 55 74 69 6C 69 74 79 2E}
		$s11 = {6E 78 65 44 52 2E 43 6F 6D 6D 61 6E 64 2B 3D 6E 65 77 20 43 6F 6D 6D 61 6E 64 45 76 65 6E 74 48 61 6E 64 6C 65 72 28 74 68 69 73 2E 69 56 6B 29 3B}
		$s12 = {3C 25 40 20 69 6D 70 6F 72 74 20 4E 61 6D 65 73 70 61 63 65 3D 5C 22 53 79 73 74 65 6D 2E 53 65 72 76 69 63 65 50 72 6F 63 65 73 73 5C 22 25 3E}
		$s13 = {66 6F 72 65 61 63 68 28 73 74 72 69 6E 67 20 69 6E 6E 65 72 53 75 62 4B 65 79 20 69 6E 20 73 6B 2E 47 65 74 53 75 62 4B 65 79 4E 61 6D 65 73 28 29 29}
		$s17 = {52 65 73 70 6F 6E 73 65 2E 52 65 64 69 72 65 63 74 28 5C 22 68 74 74 70 3A 2F 2F 77 77 77 2E 72 6F 6F 74 6B 69 74 2E 6E 65 74 2E 63 6E 5C 22 29 3B}
		$s20 = {65 6C 73 65 20 69 66 28 52 65 67 5F 50 61 74 68 2E 53 74 61 72 74 73 57 69 74 68 28 5C 22 48 4B 45 59 5F 55 53 45 52 53 5C 22 29 29}

	condition:
		6 of them
}

rule Webshell_27_9_c66_c99
{
	meta:
		description = "Detects Webshell - rule generated from from files 27.9.txt, c66.php, c99-shadows-mod.php, c99.php ..."
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
		hash2 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
		hash3 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
		hash4 = "80ec7831ae888d5603ed28d81225ed8b256c831077bb8feb235e0a1a9b68b748"
		hash5 = "6ce99e07aa98ba6dc521c34cf16fbd89654d0ba59194878dffca857a4c34e57b"
		hash6 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
		hash7 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
		hash8 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
		hash9 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		hash10 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"

	strings:
		$s4 = {69 66 20 28 21 65 6D 70 74 79 28 24 75 6E 73 65 74 5F 73 75 72 6C 29 29 20 7B 73 65 74 63 6F 6F 6B 69 65 28 5C 22 63 39 39 73 68 5F 73 75 72 6C 5C 22 29 3B 20 24 73 75 72 6C 20 3D 20 5C 22 5C 22 3B 7D}
		$s6 = {40 65 78 74 72 61 63 74 28 24 5F 52 45 51 55 45 53 54 5B 5C 22 63 39 39 73 68 63 6F 6F 6B 5C 22 5D 29 3B}
		$s7 = {69 66 20 28 21 66 75 6E 63 74 69 6F 6E 5F 65 78 69 73 74 73 28 5C 22 63 39 39 5F 62 75 66 66 5F 70 72 65 70 61 72 65 5C 22 29 29}

	condition:
		filesize <685KB and 1 of them
}

rule Webshell_acid_AntiSecShell_3
{
	meta:
		description = "Detects Webshell Acid"
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
		hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash3 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
		hash4 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
		hash5 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
		hash6 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
		hash7 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
		hash8 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
		hash9 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
		hash10 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
		hash11 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
		hash12 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash13 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
		hash14 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
		hash15 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		hash16 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
		hash17 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
		hash18 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"

	strings:
		$s0 = {65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 64 65 6C 65 74 65 5C 22 2E 28 24 64 73 70 61 63 74 20 3D 3D 20 5C 22 64 65 6C 65 74 65 5C 22 3F 5C 22 20 73 65 6C 65 63 74 65 64 5C 22 3A 5C 22 5C 22 29 2E 5C 22 3E 44 65 6C 65 74 65 3C 2F 6F 70 74 69 6F 6E 3E 5C 22 3B}
		$s1 = {69 66 20 28 21 69 73 5F 72 65 61 64 61 62 6C 65 28 24 6F 29 29 20 7B 72 65 74 75 72 6E 20 5C 22 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 5C 22 2E 76 69 65 77 5F 70 65 72 6D 73 28 66 69 6C 65 70 65 72 6D 73 28 24 6F 29 29 2E 5C 22 3C 2F 66 6F 6E 74 3E 5C 22 3B 7D}

	condition:
		filesize <900KB and all of them
}

rule Webshell_c99_4
{
	meta:
		description = "Detects C99 Webshell"
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
		hash2 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
		hash3 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
		hash4 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
		hash5 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
		hash6 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
		hash7 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
		hash8 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
		hash9 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
		hash10 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
		hash11 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash12 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		hash13 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
		hash14 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"

	strings:
		$s1 = {64 69 73 70 6C 61 79 73 65 63 69 6E 66 6F 28 5C 22 4C 69 73 74 20 6F 66 20 41 74 74 72 69 62 75 74 65 73 5C 22 2C 6D 79 73 68 65 6C 6C 65 78 65 63 28 5C 22 6C 73 61 74 74 72 20 2D 61 5C 22 29 29 3B}
		$s2 = {64 69 73 70 6C 61 79 73 65 63 69 6E 66 6F 28 5C 22 52 41 4D 5C 22 2C 6D 79 73 68 65 6C 6C 65 78 65 63 28 5C 22 66 72 65 65 20 2D 6D 5C 22 29 29 3B}
		$s3 = {64 69 73 70 6C 61 79 73 65 63 69 6E 66 6F 28 5C 22 57 68 65 72 65 20 69 73 20 70 65 72 6C 3F 5C 22 2C 6D 79 73 68 65 6C 6C 65 78 65 63 28 5C 22 77 68 65 72 65 69 73 20 70 65 72 6C 5C 22 29 29 3B}
		$s4 = {24 72 65 74 20 3D 20 6D 79 73 68 65 6C 6C 65 78 65 63 28 24 68 61 6E 64 6C 65 72 29 3B}
		$s5 = {69 66 20 28 70 6F 73 69 78 5F 6B 69 6C 6C 28 24 70 69 64 2C 24 73 69 67 29 29 20 7B 65 63 68 6F 20 5C 22 4F 4B 2E 5C 22 3B 7D}

	condition:
		filesize <900KB and 1 of them
}

rule Webshell_r57shell_2
{
	meta:
		description = "Detects Webshell R57"
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
		hash2 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
		hash3 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
		hash4 = "756b788401aad4bfd4dbafd15c382d98e3ba079390addb5b0cea7ff7f985f881"
		hash5 = "756b788401aad4bfd4dbafd15c382d98e3ba079390addb5b0cea7ff7f985f881"
		hash6 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
		hash7 = "59105e4623433d5bf93b9e17d72a43a40a4d8ac99e4a703f1d8851ad1276cd88"
		hash8 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
		hash9 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
		hash10 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
		hash11 = "59ea6cf16ea06ff47cf0e6a398df2eaec4d329707b8c3201fc63cbf0b7c85519"
		hash12 = "0e0227a0001b38fb59fc07749e80c9d298ff0e6aca126ea8f4ea68ebc9a3661f"
		hash13 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"

	strings:
		$s1 = {24 63 6F 6E 6E 65 63 74 69 6F 6E 20 3D 20 40 66 74 70 5F 63 6F 6E 6E 65 63 74 28 24 66 74 70 5F 73 65 72 76 65 72 2C 24 66 74 70 5F 70 6F 72 74 2C 31 30 29 3B}
		$s2 = {65 63 68 6F 20 24 6C 61 6E 67 5B 24 6C 61 6E 67 75 61 67 65 2E 27 5F 74 65 78 74 39 38 27 5D 2E 24 73 75 63 2E 5C 22 5C 5C 72 5C 5C 6E 5C 22 3B}

	condition:
		filesize <900KB and all of them
}

rule Webshell_27_9_acid_c99_locus7s
{
	meta:
		description = "Detects Webshell - rule generated from from files 27.9.txt, acid.php, c99_locus7s.txt"
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
		hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash3 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
		hash4 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
		hash5 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash6 = "5ae121f868555fba112ca2b1a9729d4414e795c39d14af9e599ce1f0e4e445d3"
		hash7 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		hash8 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"

	strings:
		$s0 = {24 62 6C 61 68 20 3D 20 65 78 28 24 70 32 2E 5C 22 20 2F 74 6D 70 2F 62 61 63 6B 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 62 61 63 6B 63 6F 6E 6E 65 63 74 69 70 27 5D 2E 5C 22 20 5C 22 2E 24 5F 50 4F 53 54 5B 27 62 61 63 6B 63 6F 6E 6E 65 63 74 70 6F 72 74 27 5D 2E 5C 22 20 26 5C 22 29 3B}
		$s1 = {24 5F 50 4F 53 54 5B 27 62 61 63 6B 63 63 6F 6E 6E 6D 73 67 65 27 5D 3D 5C 22 3C 2F 62 72 3E 3C 2F 62 72 3E 3C 62 3E 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 20 73 69 7A 65 3D 33 3E 45 72 72 6F 72 3A 3C 2F 66 6F 6E 74 3E 20 43 61 6E 27 74 20 62 61 63 6B 64 6F 6F 72 20 68 6F 73 74 21 3C 2F 62 3E 5C 22 3B}

	condition:
		filesize <1711KB and 1 of them
}

rule Webshell_Backdoor_PHP_Agent_r57_mod_bizzz_shell_r57
{
	meta:
		description = "Detects Webshell - rule generated from from files Backdoor.PHP.Agent.php, r57.mod-bizzz.shell.txt ..."
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
		hash2 = "f51a5c5775d9cca0b137ddb28ff3831f4f394b7af6f6a868797b0df3dcdb01ba"
		hash3 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
		hash4 = "59105e4623433d5bf93b9e17d72a43a40a4d8ac99e4a703f1d8851ad1276cd88"
		hash5 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
		hash6 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
		hash7 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
		hash8 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
		hash9 = "59ea6cf16ea06ff47cf0e6a398df2eaec4d329707b8c3201fc63cbf0b7c85519"
		hash10 = "0e0227a0001b38fb59fc07749e80c9d298ff0e6aca126ea8f4ea68ebc9a3661f"
		hash11 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"

	strings:
		$s1 = {24 5F 50 4F 53 54 5B 27 63 6D 64 27 5D 20 3D 20 77 68 69 63 68 28 27}
		$s2 = {24 62 6C 61 68 20 3D 20 65 78 28}

	condition:
		filesize <600KB and all of them
}

rule Webshell_c100
{
	meta:
		description = "Detects Webshell - rule generated from from files c100 v. 777shell"
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
		hash2 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
		hash3 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
		hash4 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
		hash5 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
		hash6 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash7 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"

	strings:
		$s0 = {3C 4F 50 54 49 4F 4E 20 56 41 4C 55 45 3D 5C 22 77 67 65 74 20 68 74 74 70 3A 2F 2F 66 74 70 2E 70 6F 77 65 72 6E 65 74 2E 63 6F 6D 2E 74 72 2F 73 75 70 65 72 6D 61 69 6C 2F 64 65 62 75 67 2F 6B 33 5C 22 3E 4B 65 72 6E 65 6C 20 61 74 74 61 63 6B 20 28 4B 72 61 64 2E 63 29 20 50 54 31 20 28 49 66 20 77 67 65 74 20 69 6E 73 74 61 6C 6C 65 64 29}
		$s1 = {3C 63 65 6E 74 65 72 3E 4B 65 72 6E 65 6C 20 49 6E 66 6F 3A 20 3C 66 6F 72 6D 20 6E 61 6D 65 3D 5C 22 66 6F 72 6D 31 5C 22 20 6D 65 74 68 6F 64 3D 5C 22 70 6F 73 74 5C 22 20 61 63 74 69 6F 6E 3D 5C 22 68 74 74 70 3A 2F 2F 67 6F 6F 67 6C 65 2E 63 6F 6D 2F 73 65 61 72 63 68 5C 22 3E}
		$s3 = {63 75 74 20 2D 64 3A 20 2D 66 31 2C 32 2C 33 20 2F 65 74 63 2F 70 61 73 73 77 64 20 7C 20 67 72 65 70 20 3A 3A}
		$s4 = {77 68 69 63 68 20 77 67 65 74 20 63 75 72 6C 20 77 33 6D 20 6C 79 6E 78}
		$s6 = {6E 65 74 73 74 61 74 20 2D 61 74 75 70 20 7C 20 67 72 65 70 20 49 53 54}

	condition:
		filesize <685KB and 2 of them
}

rule Webshell_AcidPoison
{
	meta:
		description = "Detects Poison Sh3ll - Webshell"
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash3 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
		hash4 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
		hash5 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
		hash6 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
		hash7 = "be541cf880a8e389a0767b85f1686443f35b508d1975ee25e1ce3f08fa32cfb5"
		hash8 = "be541cf880a8e389a0767b85f1686443f35b508d1975ee25e1ce3f08fa32cfb5"
		hash9 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
		hash10 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"

	strings:
		$s1 = {65 6C 73 65 69 66 20 28 20 65 6E 61 62 6C 65 64 28 5C 22 65 78 65 63 5C 22 29 20 29 20 7B 20 65 78 65 63 28 24 63 6D 64 2C 24 6F 29 3B 20 24 6F 75 74 70 75 74 20 3D 20 6A 6F 69 6E 28 5C 22 5C 5C 72 5C 5C 6E 5C 22 2C 24 6F 29 3B 20 7D}

	condition:
		filesize <550KB and all of them
}

rule Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256
{
	meta:
		description = "Detects Webshell - rule generated from from files acid.php, FaTaLisTiCz_Fx.txt, fx.txt, p0isoN.sh3ll.txt, x0rg.byp4ss.txt"
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash2 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
		hash3 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
		hash4 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
		hash5 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"

	strings:
		$s0 = {3C 66 6F 72 6D 20 6D 65 74 68 6F 64 3D 5C 22 50 4F 53 54 5C 22 3E 3C 69 6E 70 75 74 20 74 79 70 65 3D 68 69 64 64 65 6E 20 6E 61 6D 65 3D 61 63 74 20 76 61 6C 75 65 3D 5C 22 6C 73 5C 22 3E}
		$s2 = {66 6F 72 65 61 63 68 28 24 71 75 69 63 6B 6C 61 75 6E 63 68 32 20 61 73 20 24 69 74 65 6D 29 20 7B}

	condition:
		filesize <882KB and all of them
}

rule Webshell_Ayyildiz
{
	meta:
		description = "Detects Webshell - rule generated from from files Ayyildiz Tim  -AYT- Shell v 2.1 Biz.txt, Macker's Private PHPShell.php, matamu.txt, myshell.txt, PHP Shell.txt"
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "0e25aec0a9131e8c7bd7d5004c5c5ffad0e3297f386675bccc07f6ea527dded5"
		hash2 = "9c43aada0d5429f8c47595f79a7cdd5d4eb2ba5c559fb5da5a518a6c8c7c330a"
		hash3 = "2ebf3e5f5dde4a27bbd60e15c464e08245a35d15cc370b4be6b011aa7a46eaca"
		hash4 = "77a63b26f52ba341dd2f5e8bbf5daf05ebbdef6b3f7e81cec44ce97680e820f9"
		hash5 = "61c4fcb6e788c0dffcf0b672ae42b1676f8a9beaa6ec7453fc59ad821a4a8127"

	strings:
		$s0 = {65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 5C 22 2E 20 73 74 72 72 65 76 28 73 75 62 73 74 72 28 73 74 72 73 74 72 28 73 74 72 72 65 76 28 24 77 6F 72 6B 5F 64 69 72 29 2C 20 5C 22 2F 5C 22 29 2C 20 31 29 29 20 2E 5C 22 5C 5C 5C 22 3E 50 61 72 65 6E 74 20 44 69 72 65 63 74 6F 72 79 3C 2F 6F 70 74 69 6F 6E 3E 5C 5C 6E 5C 22 3B}
		$s1 = {65 63 68 6F 20 5C 22 3C 6F 70 74 69 6F 6E 20 76 61 6C 75 65 3D 5C 5C 5C 22 24 77 6F 72 6B 5F 64 69 72 5C 5C 5C 22 20 73 65 6C 65 63 74 65 64 3E 43 75 72 72 65 6E 74 20 44 69 72 65 63 74 6F 72 79 3C 2F 6F 70 74 69 6F 6E 3E 5C 5C 6E 5C 22 3B}

	condition:
		filesize <112KB and all of them
}

rule Webshell_zehir
{
	meta:
		description = "Detects Webshell - rule generated from from files elmaliseker.asp, zehir.asp, zehir.txt, zehir4.asp, zehir4.txt"
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "16e1e886576d0c70af0f96e3ccedfd2e72b8b7640f817c08a82b95ff5d4b1218"
		hash2 = "0c5f8a2ed62d10986a2dd39f52886c0900a18c03d6d279207b8de8e2ed14adf6"
		hash3 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
		hash4 = "b57bf397984545f419045391b56dcaf7b0bed8b6ee331b5c46cee35c92ffa13d"
		hash5 = "febf37a9e8ba8ece863f506ae32ad398115106cc849a9954cbc0277474cdba5c"

	strings:
		$s1 = {66 6F 72 20 28 69 3D 31 3B 20 69 3C 3D 66 72 6D 55 70 6C 6F 61 64 2E 6D 61 78 2E 76 61 6C 75 65 3B 20 69 2B 2B 29 20 73 74 72 2B 3D 27 46 69 6C 65 20 27 2B 69 2B 27 3A 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 66 69 6C 65 20 6E 61 6D 65 3D 66 69 6C 65 27 2B 69 2B 27 3E 3C 62 72 3E 27 3B}
		$s2 = {69 66 20 28 66 72 6D 55 70 6C 6F 61 64 2E 6D 61 78 2E 76 61 6C 75 65 3C 3D 30 29 20 66 72 6D 55 70 6C 6F 61 64 2E 6D 61 78 2E 76 61 6C 75 65 3D 31 3B}

	condition:
		filesize <200KB and 1 of them
}

// ===== Source: fsYara-original/low_hit/cn_pentestset_webshells.yar =====

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-06-23
	Identifier: CN-PentestSet
*/

rule CN_Honker_Webshell_PHP_php5 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php5.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0fd91b6ad400a857a6a65c8132c39e6a16712f19"
		id = "ee063c4c-af06-520f-acfe-fba758b84d3c"
	strings:
		$s0 = "else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user" ascii /* PEStudio Blacklist: strings */
		$s20 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$" ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x3f3c and filesize < 300KB and all of them
}

rule CN_Honker_Webshell_test3693 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file test3693.war"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "246d629ae3ad980b5bfe7e941fe90b855155dbfc"
		id = "58fe4445-b2e1-5d5f-8c46-39c6ae78f845"
	strings:
		$s0 = "Process p=Runtime.getRuntime().exec(\"cmd /c \"+strCmd);" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - " ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x4b50 and filesize < 50KB and all of them
}

rule CN_Honker_Webshell_mycode12 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mycode12.cfm"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "64be8760be5ab5c2dcf829e3f87d3e50b1922f17"
		id = "2ce7368c-7565-5b32-94d1-c87023404c5b"
	strings:
		$s1 = "<cfexecute name=\"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<cfoutput>#cmd#</cfoutput>" fullword ascii
	condition:
		filesize < 4KB and all of them
}

rule CN_Honker_Webshell_offlibrary {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file offlibrary.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "eb5275f99211106ae10a23b7e565d208a94c402b"
		id = "c01f7c8b-a6bd-5094-9574-8cc853698607"
	strings:
		$s0 = "';$i=$g->query(\"SELECT SUBSTRING_INDEX(CURRENT_USER, '@', 1) AS User, SUBSTRING" ascii /* PEStudio Blacklist: strings */
		$s12 = "if(jushRoot){var script=document.createElement('script');script.src=jushRoot+'ju" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 1005KB and all of them
}

rule CN_Honker_Webshell_cfm_xl {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file xl.cfm"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "49c3d16ee970945367a7d6ae86b7ade7cb3b5447"
		id = "5c8d1301-fe20-50e0-86ac-99a220cd4be1"
	strings:
		$s0 = "<input name=\"DESTINATION\" value=\"" ascii /* PEStudio Blacklist: strings */
		$s1 = "<CFFILE ACTION=\"Write\" FILE=\"#Form.path#\" OUTPUT=\"#Form.cmd#\">" fullword ascii
	condition:
		uint16(0) == 0x433c and filesize < 13KB and all of them
}

rule CN_Honker_Webshell_PHP_linux {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file linux.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "78339abb4e2bb00fe8a012a0a5b7ffce305f4e06"
		id = "8d94f1c5-2139-5d0d-8af9-9c30a0359910"
	strings:
		$s0 = "<form name=form1 action=exploit.php method=post>" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "<title>Changing CHMOD Permissions Exploit " fullword ascii
	condition:
		uint16(0) == 0x696c and filesize < 6KB and all of them
}

rule CN_Honker_Webshell_Interception3389_get {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file get.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ceb6306f6379c2c1634b5058e1894b43abcf0296"
		id = "b17a793f-ffb7-5cdc-ba21-b0e2f0d14490"
	strings:
		$s0 = "userip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "file.writeline  szTime + \" HostName:\" + szhostname + \" IP:\" + userip+\":\"+n" ascii /* PEStudio Blacklist: strings */
		$s3 = "set file=fs.OpenTextFile(server.MapPath(\"WinlogonHack.txt\"),8,True)" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 3KB and all of them
}

rule CN_Honker_Webshell_nc_1 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file 1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "51d83961171db000fe4476f36d703ef3de409676"
		id = "fe83df79-f7cb-50b8-bb34-9bfc5fbe3de2"
	strings:
		$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Mozilla/4.0 " ascii /* PEStudio Blacklist: agent */
		$s2 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
	condition:
		filesize < 11KB and all of them
}

rule CN_Honker_Webshell_PHP_BlackSky {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php6.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a60a599c6c8b6a6c0d9da93201d116af257636d7"
		id = "741bb4db-6296-5222-8480-1169a6f44fd8"
	strings:
		$s0 = "eval(gzinflate(base64_decode('" ascii /* PEStudio Blacklist: strings */
		$s1 = "B1ac7Sky-->" fullword ascii
	condition:
		filesize < 641KB and all of them
}

rule CN_Honker_Webshell_ASP_asp3 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp3.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "87c5a76989bf08da5562e0b75c196dcb3087a27b"
		id = "0cb01c07-b424-532d-8aef-5ec25dfe3f19"
	strings:
		$s1 = "if shellpath=\"\" then shellpath = \"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", Tru" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 444KB and all of them
}

rule CN_Honker_Webshell_ASPX_sniff {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file sniff.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e246256696be90189e6d50a4ebc880e6d9e28dfd"
		id = "8cf47d71-1b97-5967-ad70-2ea6fad7cc29"
	strings:
		$s1 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 91KB and all of them
}

rule CN_Honker_Webshell_udf_udf {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file udf.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "df63372ccab190f2f1d852f709f6b97a8d9d22b9"
		id = "07252f2d-1a99-5f21-940d-899a4821b511"
	strings:
		$s1 = "<?php // Source  My : Meiam  " fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 430KB and all of them
}

rule CN_Honker_Webshell_JSP_jsp {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jsp.html"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c58fed3d3d1e82e5591509b04ed09cb3675dc33a"
		id = "46f2fb10-2c0c-5bc2-b3bb-eba4c74bcad7"
	strings:
		$s1 = "<input name=f size=30 value=shell.jsp>" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<font color=red>www.i0day.com  By:" fullword ascii
	condition:
		filesize < 3KB and all of them
}

rule CN_Honker_Webshell_T00ls_Lpk_Sethc_v4_mail {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mail.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0a9b7b438591ee78ee573028cbb805a9dbb9da96"
		id = "2f7d8a4d-9d94-5f23-9768-cc3712678d93"
	strings:
		$s1 = "if (!$this->smtp_putcmd(\"AUTH LOGIN\", base64_encode($this->user)))" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "$this->smtp_debug(\"> \".$cmd.\"\\n\");" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 39KB and all of them
}

rule CN_Honker_Webshell_phpwebbackup {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file phpwebbackup.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c788cb280b7ad0429313837082fe84e9a49efab6"
		id = "eb737ea6-231c-5e8d-b976-75f1044f9f54"
	strings:
		$s0 = "<?php // Code By isosky www.nbst.org" fullword ascii
		$s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x3f3c and filesize < 67KB and all of them
}

rule CN_Honker_Webshell_dz_phpcms_phpbb {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file dz_phpcms_phpbb.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "33f23c41df452f8ca2768545ac6e740f30c44d1f"
		id = "f7e5413f-a7c9-51d4-8422-30c3e2462be2"
	strings:
		$s1 = "if($pwd == md5(md5($password).$salt))" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "function test_1($password)" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = ":\".$pwd.\"\\n---------------------------------\\n\";exit;" fullword ascii
		$s4 = ":user=\".$user.\"\\n\";echo \"pwd=\".$pwd.\"\\n\";echo \"salt=\".$salt.\"\\n\";" fullword ascii
	condition:
		filesize < 22KB and all of them
}

rule CN_Honker_Webshell_picloaked_1 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file 1.gif"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3eab1798cbc9ab3b2c67d3da7b418d07e775db70"
		id = "2ff44c4a-ed97-5635-9926-8d54a8364fab"
	strings:
		$s0 = "<?php eval($_POST[" ascii /* PEStudio Blacklist: strings */
		$s1 = ";<%execute(request(" ascii /* PEStudio Blacklist: strings */
		$s3 = "GIF89a" fullword ascii /* Goodware String - occured 318 times */
	condition:
		filesize < 6KB and 2 of them
}

rule CN_Honker_Webshell_assembly {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file assembly.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2bcb4d22758b20df6b9135d3fb3c8f35a9d9028e"
		id = "7639e81d-fe21-5a12-9a20-fe894eefef73"
	strings:
		$s0 = "response.write oScriptlhn.exec(\"cmd.exe /c\" & request(\"c\")).stdout.readall" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 1KB and all of them
}

rule CN_Honker_Webshell_PHP_php8 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php8.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b7b49f1d6645865691eccd025e140c521ff01cce"
		id = "8b25b7f3-b94e-5887-b102-b52d340a4316"
	strings:
		$s0 = "<a href=\"http://hi.baidu.com/ca3tie1/home\" target=\"_blank\">Ca3tie1's Blog</a" ascii /* PEStudio Blacklist: strings */
		$s1 = "function startfile($path = 'dodo.zip')" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<form name=\"myform\" method=\"post\" action=\"\">" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "$_REQUEST[zipname] = \"dodozip.zip\"; " fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 25KB and 2 of them
}

rule CN_Honker_Webshell_Tuoku_script_xx {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file xx.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2f39f1d9846ae72fc673f9166536dc21d8f396aa"
		id = "72a04950-b82d-516f-a376-5253b7de1158"
	strings:
		$s0 = "$mysql.=\"insert into `$table`($keys) values($vals);\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password" ascii /* PEStudio Blacklist: strings */
		$s16 = "mysql_query(\"SET NAMES gbk\");" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 2KB and all of them
}

rule CN_Honker_Webshell_JSPMSSQL {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file JSPMSSQL.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c6b4faecd743d151fe0a4634e37c9a5f6533655f"
		id = "061c1e53-edd0-5838-8d0f-6fb8f4fa078a"
	strings:
		$s1 = "<form action=\"?action=operator&cmd=execute\"" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "String sql = request.getParameter(\"sqlcmd\");" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 35KB and all of them
}

rule CN_Honker_Webshell_Injection_Transit_jmPost {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jmPost.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f80ec26bbdc803786925e8e0450ad7146b2478ff"
		id = "892f747e-6065-5baf-b928-8d69d8792483"
	strings:
		$s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 9KB and all of them
}

rule CN_Honker_Webshell_ASP_web_asp {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file web.asp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "aebf6530e89af2ad332062c6aae4a8ca91517c76"
		id = "67e03591-770a-5b32-9579-c899894740fc"
	strings:
		$s0 = "<FORM method=post target=_blank>ShellUrl: <INPUT " fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "\" >[Copy code]</a> 4ngr7&nbsp; &nbsp;</td>" fullword ascii
	condition:
		filesize < 13KB and all of them
}

rule CN_Honker_Webshell_wshell_asp {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file wshell-asp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4a0afdf5a45a759c14e99eb5315964368ca53e9c"
		id = "294f0d00-7102-553d-92e2-c0a0e017385c"
	strings:
		$s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "hello word !  " fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "root.asp " fullword ascii
	condition:
		filesize < 5KB and all of them
}

rule CN_Honker_Webshell_ASP_asp404 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp404.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bed51971288aeabba6dabbfb80d2843ec0c4ebf6"
		id = "4125bb40-3f5c-53f5-b906-54fa77b119f5"
	strings:
		$s0 = "temp1 = Len(folderspec) - Len(server.MapPath(\"./\")) -1" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "<form name=\"form1\" method=\"post\" action=\"<%= url%>?action=chklogin\">" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<td>&nbsp;<a href=\"<%=tempurl+f1.name%>\" target=\"_blank\"><%=f1.name%></a></t" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 113KB and all of them
}

rule CN_Honker_Webshell_Serv_U_asp {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file Serv-U asp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cee91cd462a459d31a95ac08fe80c70d2f9c1611"
		id = "06a58a05-92bd-5124-a172-2bfd9491c2fc"
	strings:
		$s1 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii /* PEStudio Blacklist: strings */
		$s2 = "<td><input name=\"c\" type=\"text\" id=\"c\" value=\"cmd /c net user goldsun lov" ascii /* PEStudio Blacklist: strings */
		$s3 = "deldomain = \"-DELETEDOMAIN\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \" PortNo=\"" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 30KB and 2 of them
}

rule CN_Honker_Webshell_cfm_list {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file list.cfm"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "85d445b13d2aef1df3b264c9b66d73f0ff345cec"
		id = "98302eef-d1e8-5524-a57e-d49c0e92c7e0"
	strings:
		$s1 = "<TD><a href=\"javascript:ShowFile('#mydirectory.name#')\">#mydirectory.name#</a>" ascii /* PEStudio Blacklist: strings */
		$s2 = "<TD>#mydirectory.size#</TD>" fullword ascii
	condition:
		filesize < 10KB and all of them
}

rule CN_Honker_Webshell_PHP_php2 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php2.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bf12e1d741075cd1bd324a143ec26c732a241dea"
		id = "377ff89d-a9ba-526c-97a1-388f9ccb48ba"
	strings:
		$s1 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
		$s2 = "<?php // Black" fullword ascii
	condition:
		filesize < 12KB and all of them
}

rule CN_Honker_Webshell_Tuoku_script_oracle {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file oracle.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fc7043aaac0ee2d860d11f18ddfffbede9d07957"
		id = "adc8dea6-8031-580b-b19a-e5520d41528f"
	strings:
		$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "String user=\"oracle_admin\";" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii
	condition:
		filesize < 7KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx4 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx4.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "200a8f15ffb6e3af31d28c55588003b5025497eb"
		id = "4a13c809-48f7-54f7-9ce3-10d6d48104fb"
	strings:
		$s4 = "File.Delete(cdir.FullName + \"\\\\test\");" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60" ascii /* PEStudio Blacklist: strings */
		$s6 = "<div>Code By <a href =\"http://www.hkmjj.com\">Www.hkmjj.Com</a></div>" fullword ascii
	condition:
		filesize < 11KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "8378619b2a7d446477946eabaa1e6744dec651c1"
		id = "4a13c809-48f7-54f7-9ce3-10d6d48104fb"
	strings:
		$s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii /* PEStudio Blacklist: strings */
		$s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii /* PEStudio Blacklist: strings */
		$s2 = "td.Text=\"<a href=\\\"javascript:Bin_PostBack('urJG','\"+dt.Rows[j][\"ProcessID" ascii /* PEStudio Blacklist: strings */
		$s3 = "vyX.Text+=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 353KB and 2 of them
}

rule CN_Honker_Webshell_su7_x_9_x {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file su7.x-9.x.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "808396b51023cc8356f8049cfe279b349ca08f1a"
		id = "5d546ce8-6f8f-5b0b-9472-23f283ef9f80"
	strings:
		$s0 = "returns=httpopen(\"LoginID=\"&user&\"&FullName=&Password=\"&pass&\"&ComboPasswor" ascii /* PEStudio Blacklist: strings */
		$s1 = "returns=httpopen(\"\",\"POST\",\"http://127.0.0.1:\"&port&\"/Admin/XML/User.xml?" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 59KB and all of them
}

rule CN_Honker_Webshell_cfmShell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file cfmShell.cfm"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "740796909b5d011128b6c54954788d14faea9117"
		id = "40d50ddb-2963-5d8e-b93a-bb44a8944229"
	strings:
		$s0 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "<cfif FileExists(\"#GetTempDirectory()#foobar.txt\") is \"Yes\">" fullword ascii
	condition:
		filesize < 4KB and all of them
}

rule CN_Honker_Webshell_ASP_asp4 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp4.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4005b83ced1c032dc657283341617c410bc007b8"
		id = "4125bb40-3f5c-53f5-b906-54fa77b119f5"
	strings:
		$s2 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "Response.Cookies(Cookie_Login) = sPwd" fullword ascii /* PEStudio Blacklist: strings */
		$s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 150KB and all of them
}

rule CN_Honker_Webshell_Serv_U_2_admin_by_lake2 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file Serv-U 2 admin by lake2.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cb8039f213e611ab2687edd23e63956c55f30578"
		id = "8fce8835-a4ed-58df-a725-0c1fc04becaa"
	strings:
		$s1 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/lake2\", True" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "response.write \"FTP user lake  pass admin123 :)<br><BR>\"" fullword ascii /* PEStudio Blacklist: strings */
		$s8 = "<p>Serv-U Local Get SYSTEM Shell with ASP" fullword ascii /* PEStudio Blacklist: strings */
		$s9 = "\"-HomeDir=c:\\\\\" & vbcrlf & \"-LoginMesFile=\" & vbcrlf & \"-Disable=0\" & vb" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 17KB and 2 of them
}

rule CN_Honker_Webshell_PHP_php3 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php3.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e2924cb0537f4cdfd6f1bd44caaaf68a73419b9d"
		id = "3000ac40-35de-5d24-85fb-4d105b07c2e7"
	strings:
		$s1 = "} elseif(@is_resource($f = @popen($cfe,\"r\"))) {" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "cf('/tmp/.bc',$back_connect);" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 8KB and all of them
}

rule CN_Honker_Webshell_Serv_U_by_Goldsun {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file Serv-U_by_Goldsun.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d4d7a632af65a961a1dbd0cff80d5a5c2b397e8c"
		id = "d8b85c33-b05d-531a-9c0a-a1dddcae0da4"
	strings:
		$s1 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/goldsun/upadmin/s2\", True," ascii /* PEStudio Blacklist: strings */
		$s2 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii /* PEStudio Blacklist: strings */
		$s3 = "127.0.0.1:<%=port%>," fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "GName=\"http://\" & request.servervariables(\"server_name\")&\":\"&request.serve" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 30KB and 2 of them
}

rule CN_Honker_Webshell_PHP_php10 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php10.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3698c566a0ae07234c8957112cdb34b79362b494"
		id = "5fe78cc6-8be3-595f-a082-e361259938e5"
	strings:
		$s1 = "dumpTable($N,$M,$Hc=false){if($_POST[\"format\"]!=\"sql\"){echo\"\\xef\\xbb\\xbf" ascii /* PEStudio Blacklist: strings */
		$s2 = "';if(DB==\"\"||!$od){echo\"<a href='\".h(ME).\"sql='\".bold(isset($_GET[\"sql\"]" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 600KB and all of them
}
rule CN_Honker_Webshell_Serv_U_servu {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file servu.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7de701b86820096e486e64ca34f1fa9f2fbba641"
		id = "3e50d991-7297-5766-b68a-e74aa34ce042"
	strings:
		$s0 = "fputs ($conn_id, \"SITE EXEC \".$dir.\"cmd.exe /c \".$cmd.\"\\r\\n\");" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "function ftpcmd($ftpport,$user,$password,$dir,$cmd){" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 41KB and all of them
}

rule CN_Honker_Webshell_portRecall_jsp2 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jsp2.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "412ed15eb0d24298ba41731502018800ffc24bfc"
		id = "cd34cb47-c5e0-5094-a501-6a8a00d94018"
	strings:
		$s0 = "final String remoteIP =request.getParameter(\"remoteIP\");" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "final String localIP = request.getParameter(\"localIP\");" fullword ascii /* PEStudio Blacklist: strings */
		$s20 = "final String localPort = \"3390\";//request.getParameter(\"localPort\");" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 23KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx2 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx2.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "95db7a60f4a9245ffd04c4d9724c2745da55e9fd"
		id = "0da59fde-2214-5677-943f-05b8da4fd9d4"
	strings:
		$s0 = "if (password.Equals(this.txtPass.Text))" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "<head runat=\"server\">" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x253c and filesize < 9KB and all of them
}

rule CN_Honker_Webshell_ASP_hy2006a {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file hy2006a.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "20da92b2075e6d96636f883dcdd3db4a38c01090"
		id = "115651d3-63e1-58e3-b27c-42271111bb91"
	strings:
		$s15 = "Const myCmdDotExeFile = \"command.com\"" fullword ascii /* PEStudio Blacklist: strings */
		$s16 = "If LCase(appName) = \"cmd.exe\" And appArgs <> \"\" Then" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 406KB and all of them
}

rule CN_Honker_Webshell_PHP_php1 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c2f4b150f53c78777928921b3a985ec678bfae32"
		id = "5fe78cc6-8be3-595f-a082-e361259938e5"
	strings:
		$s7 = "$sendbuf = \"site exec \".$_POST[\"SUCommand\"].\"\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
		$s8 = "elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$res = @ob_get_c" ascii /* PEStudio Blacklist: strings */
		$s18 = "echo Exec_Run($perlpath.' /tmp/spider_bc '.$_POST['yourip'].' '.$_POST['yourport" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 621KB and all of them
}

rule CN_Honker_Webshell_jspshell2 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jspshell2.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cc7bc1460416663012fc93d52e2078c0a277ff79"
		id = "ff72f94b-1c0a-5615-b35f-35f69c920292"
	strings:
		$s10 = "if (cmd == null) cmd = \"cmd.exe /c set\";" fullword ascii /* PEStudio Blacklist: strings */
		$s11 = "if (program == null) program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 424KB and all of them
}

rule CN_Honker_Webshell_Tuoku_script_mysql {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mysql.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "8e242c40aabba48687cfb135b51848af4f2d389d"
		id = "fa0627fb-a40c-5856-ae78-17d33910878f"
	strings:
		$s1 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Databas" ascii /* PEStudio Blacklist: strings */condition:
		filesize < 202KB and all of them
}

rule CN_Honker_Webshell_PHP_php9 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php9.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cd3962b1dba9f1b389212e38857568b69ca76725"
		id = "c8cbee10-78ea-5a6f-9c80-7e51a9c38440"
	strings:
		$s1 = "Str[17] = \"select shell('c:\\windows\\system32\\cmd.exe /c net user b4che10r ab" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 1087KB and all of them
}

rule CN_Honker_Webshell_portRecall_jsp {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jsp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "65e8e4d13ad257c820cad12eef853c6d0134fce8"
		id = "cd34cb47-c5e0-5094-a501-6a8a00d94018"
	strings:
		$s0 = "lcx.jsp?localIP=202.91.246.59&localPort=88&remoteIP=218.232.111.187&remotePort=2" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 1KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx3 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx3.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "dd61481771f67d9593214e605e63b62d5400c72f"
		id = "4f835136-744a-5324-a1f4-02d1cfa2cab6"
	strings:
		$s0 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m" ascii /* PEStudio Blacklist: strings */
		$s12 = "if (_Debug) System.Console.WriteLine(\"\\ninserting filename into CDS:" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 100KB and all of them
}

rule CN_Honker_Webshell_ASPX_shell_shell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file shell.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1816006827d16ed73cefdd2f11bd4c47c8af43e4"
		id = "8fbcae22-07b7-5afe-9f15-06e2f426b5ca"
	strings:
		$s0 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cook" ascii /* PEStudio Blacklist: strings */
		$s1 = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 1KB and all of them
}

rule CN_Honker_Webshell__php1_php7_php9 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - from files php1.txt, php7.txt, php9.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "c2f4b150f53c78777928921b3a985ec678bfae32"
		hash1 = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
		hash2 = "cd3962b1dba9f1b389212e38857568b69ca76725"
		id = "cfc2f624-976f-5ff6-bd07-10948b9290bc"
	strings:
		$s1 = "<a href=\"?s=h&o=wscript\">[WScript.shell]</a> " fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "document.getElementById('cmd').value = Str[i];" fullword ascii
		$s3 = "Str[7] = \"copy c:\\\\\\\\1.php d:\\\\\\\\2.php\";" fullword ascii
	condition:
		filesize < 300KB and all of them
}

rule CN_Honker_Webshell__Serv_U_by_Goldsun_asp3_Serv_U_asp {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - from files Serv-U_by_Goldsun.asp, asp3.txt, Serv-U asp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "d4d7a632af65a961a1dbd0cff80d5a5c2b397e8c"
		hash1 = "87c5a76989bf08da5562e0b75c196dcb3087a27b"
		hash2 = "cee91cd462a459d31a95ac08fe80c70d2f9c1611"
		id = "e91e05e8-0f6d-57a7-a649-a834733f17c8"
	strings:
		$s1 = "c.send loginuser & loginpass & mt & deldomain & quit" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "loginpass = \"Pass \" & pass & vbCrLf" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "b.send \"User go\" & vbCrLf & \"pass od\" & vbCrLf & \"site exec \" & cmd & vbCr" ascii
	condition:
		filesize < 444KB and all of them
}

rule CN_Honker_Webshell__asp4_asp4_MSSQL__MSSQL_ {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - from files asp4.txt, asp4.txt, MSSQL_.asp, MSSQL_.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "4005b83ced1c032dc657283341617c410bc007b8"
		hash1 = "4005b83ced1c032dc657283341617c410bc007b8"
		hash2 = "7097c21f92306983add3b5b29a517204cd6cd819"
		hash3 = "7097c21f92306983add3b5b29a517204cd6cd819"
		id = "e0070f0d-35d0-5024-88e7-e0e04b29f485"
	strings:
		$s0 = "\"<form name=\"\"searchfileform\"\" action=\"\"?action=searchfile\"\" method=\"" ascii /* PEStudio Blacklist: strings */
		$s1 = "\"<TD ALIGN=\"\"Left\"\" colspan=\"\"5\"\">[\"& DbName & \"]" fullword ascii
		$s2 = "Set Conn = Nothing " fullword ascii
	condition:
		filesize < 341KB and all of them
}

rule CN_Honker_Webshell__Injection_jmCook_jmPost_ManualInjection {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - from files Injection.exe, jmCook.asp, jmPost.asp, ManualInjection.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "3484ed16e6f9e0d603cbc5cb44e46b8b7e775d35"
		hash1 = "5e1851c77ce922e682333a3cb83b8506e1d7395d"
		hash2 = "f80ec26bbdc803786925e8e0450ad7146b2478ff"
		hash3 = "e83d427f44783088a84e9c231c6816c214434526"
		id = "e154ecb5-9d56-520a-b76a-635a8864f0a8"
	strings:
		$s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "strReturn=Replace(strReturn,chr(43),\"%2B\")  'JMDCW" fullword ascii
	condition:
		filesize < 7342KB and all of them
}

rule CN_Honker_Webshell_cmfshell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file cmfshell.cmf"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b9b2107c946431e4ad1a8f5e53ac05e132935c0e"
		id = "c5670deb-952c-5ba4-949a-097cc09bb108"
	strings:
		$s1 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<form action=\"<cfoutput>#CGI.SCRIPT_NAME#</cfoutput>\" method=\"post\">" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 4KB and all of them
}

rule CN_Honker_Webshell_PHP_php4 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php4.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "179975f632baff6ee4d674fe3fabc324724fee9e"
		id = "82446dff-dd1e-54a8-bb70-570bedc805b5"
	strings:
		$s0 = "nc -l -vv -p port(" ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x4850 and filesize < 1KB and all of them
}

rule CN_Honker_Webshell_Linux_2_6_Exploit {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file 2.6.9"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ec22fac0510d0dc2c29d56c55ff7135239b0aeee"
		id = "22e2aca7-418f-598f-af0c-99942aaf3278"
	strings:
		$s0 = "[+] Failed to get root :( Something's wrong.  Maybe the kernel isn't vulnerable?" fullword ascii
	condition:
		filesize < 56KB and all of them
}

rule CN_Honker_Webshell_ASP_asp2 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp2.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b3ac478e72a0457798a3532f6799adeaf4a7fc87"
		id = "e5296405-c345-55dc-acd9-be6aca86c60b"
	strings:
		$s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "webshell</font> <font color=#00FF00>" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Userpwd = \"admin\"   'User Password" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 10KB and all of them
}

rule CN_Honker_Webshell_FTP_MYSQL_MSSQL_SSH {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file FTP MYSQL MSSQL SSH.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fe63b215473584564ef2e08651c77f764999e8ac"
		id = "dd619901-6f0e-527e-9926-808176641c09"
	strings:
		$s1 = "$_SESSION['hostlist'] = $hostlist = $_POST['hostlist'];" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Codz by <a href=\"http://www.sablog.net/blog\">4ngel</a><br />" fullword ascii
		$s3 = "if ($conn_id = @ftp_connect($host, $ftpport)) {" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "$_SESSION['sshport'] = $mssqlport = $_POST['sshport'];" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "<title>ScanPass(FTP/MYSQL/MSSQL/SSH) by 4ngel</title>" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 20KB and 3 of them
}

rule CN_Honker_Webshell_ASP_shell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file shell.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b7b34215c2293ace70fc06cbb9ce73743e867289"
		id = "fdfc3fc1-9400-533b-978b-1a1fac112e1f"
	strings:
		$s1 = "xPost.Open \"GET\",\"http://www.i0day.com/1.txt\",False //" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "sGet.SaveToFile Server.MapPath(\"test.asp\"),2 //" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "http://hi.baidu.com/xahacker/fuck.txt" fullword ascii
	condition:
		filesize < 1KB and all of them
}

rule CN_Honker_Webshell_PHP_php7 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php7.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
		id = "f21bb0db-d18a-58c0-a227-5baf5536c57b"
	strings:
		$s0 = "---> '.$ports[$i].'<br>'; ob_flush(); flush(); } } echo '</div>'; return true; }" ascii /* PEStudio Blacklist: strings */
		$s1 = "$getfile = isset($_POST['downfile']) ? $_POST['downfile'] : ''; $getaction = iss" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 300KB and all of them
}

rule CN_Honker_Webshell_ASP_rootkit {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file rootkit.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3bfc1c95782e702cf56184e7d438edcf5802eab3"
		id = "ab51abca-0790-541c-9f18-1568809ef113"
	strings:
		$s0 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 80KB and all of them
}

rule CN_Honker_Webshell_jspshell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jspshell.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d16af622f7688d4e0856a2678c4064d3d120e14b"
		id = "ff72f94b-1c0a-5615-b35f-35f69c920292"
	strings:
		$s1 = "else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Proce" ascii /* PEStudio Blacklist: strings */
		$s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 30KB and all of them
}

rule CN_Honker_Webshell_Serv_U_serv_u {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file serv-u.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2023-01-27"
		score = 70
		hash = "1c6415a247c08a63e3359b06575b36017befc0c0"
		id = "dd37b2c3-e06d-5245-97d7-40e5eeadb76f"
	strings:
		$s1 = "@readfile(\"c:\\\\winnt\\\\system32\\" ascii /* PEStudio Blacklist: strings */
		$s2 = "$sendbuf = \"PASS \".$_POST[\"password\"].\"\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "$cmd=\"cmd /c rundll32.exe $path,install $openPort $activeStr\";" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 435KB and all of them
}

rule CN_Honker_Webshell_WebShell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file WebShell.cgi"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"
		id = "9fe4c8fd-3955-5405-add2-835e6f64e8f2"
	strings:
		$s1 = "$login = crypt($WebShell::Configuration::password, $salt);" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "warn \"command: '$command'\\n\";" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 30KB and 2 of them
}

rule CN_Honker_Webshell_Tuoku_script_mssql_2 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mssql.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ad55512afa109b205e4b1b7968a89df0cf781dc9"
		id = "3f9706d6-7f6e-5120-945a-d5d928d79507"
	strings:
		$s1 = "sqlpass=request(\"sqlpass\")" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<blockquote> ServerIP:&nbsp;&nbsp;&nbsp;" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 3KB and all of them
}

rule CN_Honker_Webshell_ASP_asp1 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "78b5889b363043ed8a60bed939744b4b19503552"
		id = "bf0b1f1e-cf7b-5afb-8e0a-bcfd70fc8887"
	strings:
		$s1 = "SItEuRl=" ascii
		$s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Server.ScriptTimeout=" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 200KB and all of them
}

// ===== Source: fsYara-original/low_hit/gen_cn_webshells.yar =====

/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-06-13
    Identifier: CN-Tools Webshells
    Reference: Diclosed hacktool set at http://w2op.us/ (Mirror: http://tools.zjqhr.com)
*/


rule Tools_cmd {
    meta:
        description = "Chinese Hacktool Set - file cmd.jSp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "02e37b95ef670336dc95331ec73dbb5a86f3ba2b"
        id = "27c3cb44-9351-52a2-8e14-afade14e3384"
    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"Conn\"" ascii
        $s2 = "<%@ page import=\"java.io.*\" %>" fullword ascii
        $s3 = "out.print(\"Hi,Man 2015<br /><!--?Confpwd=023&Conn=ls-->\");" fullword ascii
        $s4 = "while((a=in.read(b))!=-1){" fullword ascii
        $s5 = "out.println(new String(b));" fullword ascii
        $s6 = "out.print(\"</pre>\");" fullword ascii
        $s7 = "out.print(\"<pre>\");" fullword ascii
        $s8 = "int a = -1;" fullword ascii
        $s9 = "byte[] b = new byte[2048];" fullword ascii
    condition:
        filesize < 3KB and 7 of them
}


rule trigger_drop {
    meta:
        description = "Chinese Hacktool Set - file trigger_drop.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "165dd2d82bf87285c8a53ad1ede6d61a90837ba4"
        id = "3b4f32ff-2de2-5689-869a-8a8f55e7fa0c"
    strings:
        $s0 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
        $s1 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
        $s2 = "@mssql_query('DROP TRIGGER" ascii
        $s3 = "if(empty($_GET['returnto']))" fullword ascii
    condition:
        filesize < 5KB and all of them
}

rule InjectionParameters {
    meta:
        description = "Chinese Hacktool Set - file InjectionParameters.vb"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "4f11aa5b3660c45e527606ee33de001f4994e1ea"
        id = "a77bd0c6-8857-577f-831a-0fcf2537667e"
    strings:
        $s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
        $s1 = "Public Class InjectionParameters" fullword ascii
    condition:
        filesize < 13KB and all of them
}

rule users_list {
    meta:
        description = "Chinese Hacktool Set - file users_list.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6fba1a1a607198ed232405ccbebf9543037a63ef"
        id = "2d90b593-6b65-502c-aeb0-8f2a3d65afd3"
    strings:
        $s0 = "<a href=\"users_create.php\">Create User</a>" fullword ascii
        $s7 = "$skiplist = array('##MS_AgentSigningCertificate##','NT AUTHORITY\\NETWORK SERVIC" ascii
        $s11 = "&nbsp;<b>Default DB</b>&nbsp;" fullword ascii
    condition:
        filesize < 12KB and all of them
}

rule trigger_modify {
    meta:
        description = "Chinese Hacktool Set - file trigger_modify.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "c93cd7a6c3f962381e9bf2b511db9b1639a22de0"
        id = "a7d65a9f-82de-554c-8f20-7560d2160041"
    strings:
        $s1 = "<form name=\"form1\" method=\"post\" action=\"trigger_modify.php?trigger=<?php e" ascii
        $s2 = "$data_query = @mssql_query('sp_helptext \\'' . urldecode($_GET['trigger']) . '" ascii
        $s3 = "if($_POST['query'] != '')" fullword ascii
        $s4 = "$lines[] = 'I am unable to read this trigger.';" fullword ascii
        $s5 = "<b>Modify Trigger</b>" fullword ascii
    condition:
        filesize < 15KB and all of them
}

rule Customize {
    meta:
        description = "Chinese Hacktool Set - file Customize.aspx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "db556879dff9a0101a7a26260a5d0dc471242af2"
        id = "a69e1234-cc85-5295-a45c-693afdfc368e"
    strings:
        $s1 = "ds.Clear();ds.Dispose();}else{SqlCommand cm = Conn.CreateCommand();cm.CommandTex" ascii
        $s2 = "c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=tr" ascii
        $s3 = "Stream WF=WB.GetResponseStream();FileStream FS=new FileStream(Z2,FileMode.Create" ascii
        $s4 = "R=\"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";}Conn.Close();break;" ascii
    condition:
        filesize < 24KB and all of them
}

rule oracle_data {
    meta:
        description = "Chinese Hacktool Set - file oracle_data.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6cf070017be117eace4752650ba6cf96d67d2106"
        id = "faa62dcc-0f59-573c-8722-d07216de151f"
    strings:
        $s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
        $s1 = "if(isset($_REQUEST['id']))" fullword ascii
        $s2 = "$id=$_REQUEST['id'];" fullword ascii
    condition:
        all of them
}

rule reDuhServers_reDuh {
    meta:
        description = "Chinese Hacktool Set - file reDuh.jsp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "377886490a86290de53d696864e41d6a547223b0"
        id = "c87d971a-a16f-5593-88fb-6bcd207e0841"
    strings:
        $s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
        $s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
        $s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
    condition:
        filesize < 116KB and all of them
}

rule item_old {
    meta:
        description = "Chinese Hacktool Set - file item-old.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "daae358bde97e534bc7f2b0134775b47ef57e1da"
        id = "c32bbd48-a363-53c7-84c6-c47581e2f9da"
    strings:
        $s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
        $s3 = "$sHash = md5($sURL);" fullword ascii
    condition:
        filesize < 7KB and 2 of them
}

rule Tools_2014 {
    meta:
        description = "Chinese Hacktool Set - file 2014.jsp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "74518faf08637c53095697071db09d34dbe8d676"
        id = "bb76321b-003d-5f6b-a84b-425477abe91c"
    strings:
        $s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
    condition:
        filesize < 715KB and all of them
}

rule reDuhServers_reDuh_2 {
    meta:
        description = "Chinese Hacktool Set - file reDuh.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "512d0a3e7bb7056338ad0167f485a8a6fa1532a3"
        id = "6050dfde-6c79-5dd8-a772-508668177aa5"
    strings:
        $s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
        $s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
        $s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
    condition:
        filesize < 57KB and all of them
}

rule Customize_2 {
    meta:
        description = "Chinese Hacktool Set - file Customize.jsp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "37cd17543e14109d3785093e150652032a85d734"
        id = "1f7e9063-33d8-5df4-89d5-7d8fc1be61f0"
    strings:
        $s1 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}}" fullword ascii
        $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
    condition:
        filesize < 30KB and all of them
}

rule ChinaChopper_one {
    meta:
        description = "Chinese Hacktool Set - file one.asp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6cd28163be831a58223820e7abe43d5eacb14109"
        id = "854fb5c9-38c7-5fd2-a473-66ae297070f5"
    strings:
        $s0 = "<%eval request(" ascii
    condition:
        filesize < 50 and all of them
}

rule CN_Tools_old {
    meta:
        description = "Chinese Hacktool Set - file old.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "f8a007758fda8aa1c0af3c43f3d7e3186a9ff307"
        id = "bfdb84e8-e5a8-53a4-ae71-e0d1b38d38ef"
    strings:
        $s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
        $s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
        $s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii
    condition:
        filesize < 6KB and all of them
}

rule item_301 {
    meta:
        description = "Chinese Hacktool Set - file item-301.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "15636f0e7dc062437608c1f22b1d39fa15ab2136"
        id = "4ee9a089-313f-53c1-8196-1348d721dbf4"
    strings:
        $s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
        $s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
        $s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
        $s4 = "$sURL = $aArg[0];" fullword ascii
    condition:
        filesize < 3KB and 3 of them
}

rule CN_Tools_item {
    meta:
        description = "Chinese Hacktool Set - file item.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "a584db17ad93f88e56fd14090fae388558be08e4"
        id = "954f24c9-d7d5-56d3-86f0-0cf8832640dd"
    strings:
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s3 = "$sWget=\"index.asp\";" fullword ascii
        $s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
    condition:
        filesize < 4KB and all of them
}

rule f3_diy {
    meta:
        description = "Chinese Hacktool Set - file diy.asp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "f39c2f64abe5e86d8d36dbb7b1921c7eab63bec9"
        id = "9f36c6dd-89e8-511b-a499-131f1e8a420a"
    strings:
        $s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
        $s5 = ".black {" fullword ascii
    condition:
        uint16(0) == 0x253c and filesize < 10KB and all of them
}

rule ChinaChopper_temp {
    meta:
        description = "Chinese Hacktool Set - file temp.asp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "b0561ea52331c794977d69704345717b4eb0a2a7"
        id = "f163787f-fcc9-568a-a12d-4057cb4f0d29"
    strings:
        $s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
        $s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
        $s2 = "o.language = \"vbscript\"" fullword ascii
        $s3 = "o.addcode(Request(\"SC\"))" fullword ascii
    condition:
        filesize < 1KB and all of them
}

rule Tools_2015 {
    meta:
        description = "Chinese Hacktool Set - file 2015.jsp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "8fc67359567b78cadf5d5c91a623de1c1d2ab689"
        id = "eb2826ab-ef8d-5a93-9ede-f5bbd7ab4ff4"
    strings:
        $s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
        $s4 = "System.out.println(Oute.toString());" fullword ascii
        $s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
        $s8 = "HttpURLConnection httpUrl = null;" fullword ascii
        $s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
    condition:
        filesize < 7KB and all of them
}

rule ChinaChopper_temp_2 {
    meta:
        description = "Chinese Hacktool Set - file temp.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "604a4c07161ce1cd54aed5566e5720161b59deee"
        id = "3952ed2b-fb27-5c45-9cd7-b7a300b37c0e"
    strings:
        $s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
    condition:
        filesize < 150 and all of them
}

rule templatr {
    meta:
        description = "Chinese Hacktool Set - file templatr.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "759df470103d36a12c7d8cf4883b0c58fe98156b"
        id = "b361a49d-1e05-5597-bf8b-735e04397ffa"
    strings:
        $s0 = "eval(gzinflate(base64_decode('" ascii
    condition:
        filesize < 70KB and all of them
}

rule reDuhServers_reDuh_3 {
    meta:
        description = "Chinese Hacktool Set - file reDuh.aspx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "0744f64c24bf4c0bef54651f7c88a63e452b3b2d"
        id = "69f5fd6b-a9b3-500b-8723-d1c82494903d"
    strings:
        $s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
        $s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
        $s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
        $s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
    condition:
        filesize < 40KB and all of them
}

rule ChinaChopper_temp_3 {
    meta:
        description = "Chinese Hacktool Set - file temp.aspx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
        id = "573e7da6-f58f-5814-b3e8-a0db3ecfe558"
    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
        $s1 = "\"],\"unsafe\");%>" ascii
    condition:
        uint16(0) == 0x253c and filesize < 150 and all of them
}

rule Shell_Asp {
    meta:
        description = "Chinese Hacktool Set Webshells - file Asp.html"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "5e0bc914ac287aa1418f6554ddbe0ce25f2b5f20"
        id = "52089205-8f36-5a0b-a1ae-67c91a253ad2"
    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "function Command(cmd, str){" fullword ascii
    condition:
        filesize < 100KB and all of them
}


rule Txt_aspxtag {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspxtag.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "42cb272c02dbd49856816d903833d423d3759948"
        id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
    strings:
        $s1 = "String wGetUrl=Request.QueryString[" fullword ascii
        $s2 = "sw.Write(wget);" fullword ascii
        $s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii
    condition:
        filesize < 2KB and all of them
}

rule Txt_php {
    meta:
        description = "Chinese Hacktool Set - Webshells - file php.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "eaa1af4b898f44fc954b485d33ce1d92790858d0"
        id = "65d5c46f-006d-58f9-bb7f-0a2e1f1853bd"
    strings:
        $s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
        $s2 = "gzuncompress($_SESSION['api']),null);" ascii
        $s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
        $s4 = "if(empty($_SESSION['api']))" fullword ascii
    condition:
        filesize < 1KB and all of them
}

rule Txt_aspx1 {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
        id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item["
        $s1 = "],\"unsafe\");%>" fullword ascii
    condition:
        filesize < 150 and all of them
}

rule Txt_shell {
    meta:
        description = "Chinese Hacktool Set - Webshells - file shell.c"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "8342b634636ef8b3235db0600a63cc0ce1c06b62"
        id = "3e4c5928-346e-541b-b1a8-b37d5e3abc98"
    strings:
        $s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
        $s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
        $s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
        $s4 = "char shell[]=\"/bin/sh\";" fullword ascii
        $s5 = "connect back door\\n\\n\");" fullword ascii
    condition:
        filesize < 2KB and 2 of them
}

rule Txt_asp {
    meta:
        description = "Chinese Hacktool Set - Webshells - file asp.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "a63549f749f4d9d0861825764e042e299e06a705"
        id = "39a2ba9a-c429-574f-8820-5e0270a4b84c"
    strings:
        $s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
        $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
    condition:
        uint16(0) == 0x253c and filesize < 100KB and all of them
}

rule Txt_asp1 {
    meta:
        description = "Chinese Hacktool Set - Webshells - file asp1.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "95934d05f0884e09911ea9905c74690ace1ef653"
        id = "b00ab02c-c767-568c-be99-6cc731c3f1dc"
    strings:
        $s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
        $s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
        $s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii
    condition:
        filesize < 70KB and 2 of them
}

rule Txt_php_2 {
    meta:
        description = "Chinese Hacktool Set - Webshells - file php.html"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "a7d5fcbd39071e0915c4ad914d31e00c7127bcfc"
        id = "66916e32-9471-54bd-944e-bb751b38d3b0"
    strings:
        $s1 = "function connect($dbhost, $dbuser, $dbpass, $dbname='') {" fullword ascii
        $s2 = "scookie('loginpass', '', -86400 * 365);" fullword ascii
        $s3 = "<title><?php echo $act.' - '.$_SERVER['HTTP_HOST'];?></title>" fullword ascii
        $s4 = "Powered by <a title=\"Build 20130112\" href=\"http://www.4ngel.net\" target=\"_b" ascii
        $s5 = "formhead(array('title'=>'Execute Command', 'onsubmit'=>'g(\\'shell\\',null,this." ascii
        $s6 = "secparam('IP Configurate',execute('ipconfig -all'));" fullword ascii
        $s7 = "secparam('Hosts', @file_get_contents('/etc/hosts'));" fullword ascii
        $s8 = "p('<p><a href=\"http://w'.'ww.4'.'ng'.'el.net/php'.'sp'.'y/pl'.'ugin/\" target=" ascii
    condition:
        filesize < 100KB and 4 of them
}

rule Txt_ftp {
    meta:
        description = "Chinese Hacktool Set - Webshells - file ftp.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "3495e6bcb5484e678ce4bae0bd1a420b7eb6ad1d"
        id = "311de4b0-fa19-545a-8a65-a40b255b5b39"
    strings:
        $s1 = "';exec master.dbo.xp_cmdshell 'echo open " ascii
        $s2 = "';exec master.dbo.xp_cmdshell 'ftp -s:';" ascii
        $s3 = "';exec master.dbo.xp_cmdshell 'echo get lcx.exe" ascii
        $s4 = "';exec master.dbo.xp_cmdshell 'echo get php.exe" ascii
        $s5 = "';exec master.dbo.xp_cmdshell 'copy " ascii
        $s6 = "ftp -s:d:\\ftp.txt " fullword ascii
        $s7 = "echo bye>>d:\\ftp.txt " fullword ascii
    condition:
        filesize < 2KB and 2 of them
}

rule Txt_lcx {
    meta:
        description = "Chinese Hacktool Set - Webshells - file lcx.c"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "ddb3b6a5c5c22692de539ccb796ede214862befe"
        id = "4a4e8810-6dae-526e-86f0-43de45d1c87a"
    strings:
        $s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
        $s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
        $s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
        $s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
        $s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii
    condition:
        filesize < 25KB and 2 of them
}

rule Txt_jspcmd {
    meta:
        description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "1d4e789031b15adde89a4628afc759859e53e353"
        id = "53eb6caf-3578-5df7-a1d8-9e4038b6f57e"
    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
    condition:
        filesize < 1KB and 1 of them
}

rule Txt_jsp {
    meta:
        description = "Chinese Hacktool Set - Webshells - file jsp.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "74518faf08637c53095697071db09d34dbe8d676"
        id = "53eb6caf-3578-5df7-a1d8-9e4038b6f57e"
    strings:
        $s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
        $s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $s4 = "cmd = \"cmd.exe /c set\";" fullword ascii
    condition:
        filesize < 715KB and 2 of them
}

rule Txt_aspxlcx {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "453dd3160db17d0d762e032818a5a10baf234e03"
        id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
    strings:
        $s1 = "public string remoteip = " ascii
        $s2 = "=Dns.Resolve(host);" ascii
        $s3 = "public string remoteport = " ascii
        $s4 = "public class PortForward" ascii
    condition:
        uint16(0) == 0x253c and filesize < 18KB and all of them
}

rule Txt_xiao {
    meta:
        description = "Chinese Hacktool Set - Webshells - file xiao.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "b3b98fb57f5f5ccdc42e746e32950834807903b7"
        id = "cd375597-c343-5f7d-8574-23f700ff432b"
    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED," ascii
        $s4 = "function Command(cmd, str){" fullword ascii
        $s5 = "echo \"if(obj.value=='PageWebProxy')obj.form.target='_blank';\"" fullword ascii
    condition:
        filesize < 100KB and all of them
}

rule Txt_aspx {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspx.jpg"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "ce24e277746c317d887139a0d71dd250bfb0ed58"
        id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
    strings:
        $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
        $s2 = "Process[] p=Process.GetProcesses();" fullword ascii
        $s3 = "Copyright &copy; 2009 Bin" ascii
        $s4 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"serv" ascii
    condition:
        filesize < 100KB and all of them
}

rule Txt_Sql {
    meta:
        description = "Chinese Hacktool Set - Webshells - file Sql.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "f7813f1dfa4eec9a90886c80b88aa38e2adc25d5"
        id = "586f23d4-3a04-520d-b75b-f9bbcf67ceeb"
    strings:
        $s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
        $s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
        $s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
        $s4 = "session(\"login\")=\"\"" fullword ascii
    condition:
        filesize < 15KB and all of them
}

rule Txt_hello {
    meta:
        description = "Chinese Hacktool Set - Webshells - file hello.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "697a9ebcea6a22a16ce1a51437fcb4e1a1d7f079"
        id = "42d01411-e333-543d-84a2-758c13bad2df"
    strings:
        $s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
        $s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
        $s2 = "myProcess.Start()" fullword ascii
        $s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii
    condition:
        filesize < 25KB and all of them
}
