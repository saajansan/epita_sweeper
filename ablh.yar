rule cybsecmalware_obfuscated : PDF 
{
    meta:
        description = "Obfuscated PDF initializer"
        author = "team epita"
        date = "2023-06-06"

    strings:
        $header = "%PDF"
        $js_obfuscation = /\/AA\s<<.*>>\s>>\s\/OpenAction/ nocase wide
        $string_encoding = /\/Type\s\/Action\s\/S\/JavaScript\s\/JS \((\\[0-9a-f]{2}|[^)])*\)/ nocase wide

    condition:
              $header at 0 and (any of ($js_obfuscation, $string_encoding))
}

rule jscodeexploits_obfuscated : PDF
{
    meta:
        description = "Obfuscated PDF with JS code and exploitable vuln"
        author = "team epita"
        date = "2023-06-06"

    strings:
        //$header = "%PDF"
        $js_obfuscation = /\/JS\s\((\\[0-9a-f]{2}|[^)])*\)/ nocase wide

    condition:
              //$header at 0 and 
              $js_obfuscation
}

rule js_hashbased_signatures_obfuscated : PDF
{
    meta:
        description = "Based on embedded JS code hashes and link vuln (with obfuscation)"
        author = "team epita"
        date = "2023-06-06"

    strings:
        $header = "%PDF"
        $js_obfuscation = /\/JS\s\((\\[0-9a-f]{2}|[^)])*\)/ nocase wide
        $array_obfuscation = /\[[0-9a-fA-F]+\]/ wide
        $hex_encoding = /<[0-9a-fA-F]+>/ wide
        $base64_encoding = /[0-9a-zA-Z+\/=]{30,}/ wide

    condition:
              $header at 0 and (any of ($js_obfuscation, $array_obfuscation, $hex_encoding, $base64_encoding))
}

rule Strings_obfuscated : PDF
{
    meta:
        description = "Malware - Obfuscated file igotyou.pdf"
        author = "epicybsec"
        date = "2023-06-30"
        hash1 = "dd29c94a866d784dbee1d52f2d3d5fa1a288f6a9935b54097595b6c6fb1641eb"

    strings:
        $header = "%PDF"
        $string_encoding = /<<\s*\/Length\s+\d+\s*\/Filter\s*\/FlateDecode\s*>>\s*stream\s*((\\[0-9a-f]{2}|[^)])*)\s*endstream/ nocase ascii wide
        $base64_encoding = /<<\s*\/Filter\s*\/FlateDecode\s*>>\s*stream\s*([0-9a-zA-Z+\/=]{30,})\s*endstream/ nocase ascii wide

    condition:
              $header at 0 and (any of ($string_encoding, $base64_encoding))
}

rule PDF_Embedded_Exe_Obfuscated : PDF
{
    meta:
        description = "Obfuscated file based on embedded functions"
    
    strings:
        $header = "%PDF"
        $string_encoding = /\/Length\s+\d+\s*\/Filter\s*\/FlateDecode\s*\/Type\s*\/XObject\s*\/Subtype\s*\/Image/ nocase wide
        $base64_encoding = /\/Filter\s*\/FlateDecode\s*\/Length\s+\d+\s*>>\s*stream\s*[0-9a-zA-Z+\/=]{30,}\s*endstream/ nocase wide

    condition:
        $header at 0 and (any of ($string_encoding, $base64_encoding))
}

rule js_wrong_version_obfuscated : PDF raw
{
	meta:
		author = "epicyber sec"
		description = "Obfuscated JavaScript was injected"
		version = "0.2"
		weight = 2
		
    strings:
                $header = "%PDF"
		$string_encoding = /<<\s*\/Length\s+\d+\s*\/Filter\s*\/FlateDecode\s*>>\s*stream\s*((\\[0-9a-f]{2}|[^)])*)\s*endstream/ nocase ascii wide
		$base64_encoding = /<<\s*\/Filter\s*\/FlateDecode\s*>>\s*stream\s*([0-9a-zA-Z+\/=]{30,})\s*endstream/ nocase ascii wide
		$hex_encoding = /\/HEX\s*<[0-9a-fA-F\s]+>/ nocase wide
		$array_obfuscation = /\[[0-9a-fA-F]+\]/ wide

    condition:
             $header at 0 and (any of ($string_encoding, $base64_encoding, $hex_encoding, $array_obfuscation))
}

rule invalid_trailer_structure_obfuscated : PDF raw
{
	meta:
		author = "epicybersec"
		weight = 2

	strings:
		$header = "%PDF"
		$string_encoding = /<<\s*\/Length\s+\d+\s*\/Filter\s*\/FlateDecode\s*>>\s*stream\s*((\\[0-9a-f]{2}|[^)])*)\s*endstream/ nocase ascii wide
		$base64_encoding = /<<\s*\/Filter\s*\/FlateDecode\s*>>\s*stream\s*([0-9a-zA-Z+\/=]{30,})\s*endstream/ nocase ascii wide
		$hex_encoding = /\/HEX\s*<[0-9a-fA-F\s]+>/ nocase wide
		$array_obfuscation = /\[[0-9a-fA-F]+\]/ wide

	condition:
		$header at 0 and (any of ($string_encoding, $base64_encoding, $hex_encoding, $array_obfuscation))
}