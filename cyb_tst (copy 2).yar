rule cybsecmalware : PDF 
{
    meta:
        description = "pdf initializer"
        author = "team epita"
        date = "2023-06-06"

    strings:
        $magic = { 25 50 44 46 }
        $header = /%PDF-1\.(2|3|4|6|7)/
        $reg0  = /Title.?\(who is\)/

    condition:
        $magic in (0..1024) and $header and $reg0
}

rule jscodeexploits : PDF
{
    meta:
        description = "js code and exploitable vuln"
        author = "team epita"
        date = "2023-06-06"

    strings:
        $magic = { 25 50 44 46 }
        $attrib0 = /\/ASCIIHexDecode/
        $attrib1 = /\/JavaScript /
        $attrib2 = /\/ASCII85Decode/

    condition:
        $magic in (0..1024) and all of ($attrib*)
}

rule js_hashbased_signatures : PDF
{
    meta:
        description = "based on embedded js.code hashes and link vuln"
        author = "team epita"
        date = "2023-06-06"

    strings:
        $magic = { 25 50 44 46 }
        $s1 = "/S /JavaScript" fullword ascii
        $s2 = "/F (\\\\\\\\xbci400162ytrokd7nl20m3vhmndb2.oastify.com\\\\)"
        $s3 = "/Contents 5 0 R" fullword ascii
        $s4 = "020202020202020202020202020202072657475726E2066616C73653B0A0A2020202020202020575B22536122202B20227665546F22202B202246696C65225D2" ascii
        $s5 = "6617220723D33363132333B0A0A202020202020202076617220583D722B33363030353B0A0A202020202020202076617220673D582F3138343B0A0A202020202" ascii
        $s6 = "06B2829293B0A0A20202020202020207661722057203D206E6577206D6A282241444F44422E53747265616D22293B0A0A20202020202020204B203D207142452" ascii  
        $s7 = "A203D20634E283432293B0A0A0A0A2020202020202020766172207A73203D206E6577206D6A28224D22202B202253584D22202B2050682829293B0A0A2020202" ascii
        $s8 = "909096A6F766375776F203D20273331343330273B0A090909090909717275646D697864616C203D20383B0A09090909090976617220656875746577617376203" ascii
        $s9 = "trailer" fullword ascii
        $s10 = "%%EOF" fullword ascii
              
    condition:
        $magic in (0..1024) and all of ($s*)
}

rule _home_kali_Desktop_malware_igotyou {
   meta:
      description = "malware - file igotyou.pdf"
      author = "epicybsec"
      date = "2023-06-30"
      hash1 = "dd29c94a866d784dbee1d52f2d3d5fa1a288f6a9935b54097595b6c6fb1641eb"
   strings:
      $s1 = "<</Size 13/Info 5 0 R/Root 2 0 R/ID[<A3917BD562BB9C40838A780085EC8365><6CE63827AE7877A4789A3691A9A2B81C>]/Encrypt<</Filter/Stand" ascii
      $s2 = "<</Size 13/Info 5 0 R/Root 2 0 R/ID[<A3917BD562BB9C40838A780085EC8365><6CE63827AE7877A4789A3691A9A2B81C>]/Encrypt<</Filter/Stand" ascii
      $s3 = "ard/R 2/V 1/Length 40/P -4/EncryptMetadata true/O<2055C756C72E1AD702608E8196ACAD447AD32D17CFF583235F6DD15FED7DAB67>/U<2EF3059FBF" ascii
      $s4 = "<</Contents 11 0 R/CropBox[0 0 828 1204]/MediaBox[0 0 828 1204]/Parent 4 0 R/Resources<</ProcSet[/PDF/ImageC]/XObject<</Im0 9 0 " ascii
      $s5 = "<</BitsPerComponent 8/ColorSpace/DeviceRGB/Width 828/Height 1204/Length 278678/Metadata 10 0 R/Name/X/Subtype/Image/Type/XObject" ascii
      $s6 = "<</Contents 11 0 R/CropBox[0 0 828 1204]/MediaBox[0 0 828 1204]/Parent 4 0 R/Resources<</ProcSet[/PDF/ImageC]/XObject<</Im0 9 0 " ascii
      $s7 = "@Ch:\\3x7&" fullword ascii
      $s8 = "<</BitsPerComponent 8/ColorSpace/DeviceRGB/Width 828/Height 1204/Length 278678/Metadata 10 0 R/Name/X/Subtype/Image/Type/XObject" ascii
      $s9 = "/Filter/FlateDecode>>" fullword ascii
      $s10 = "<</P 0/S 40/Length 57/Filter/FlateDecode>>" fullword ascii
      $s11 = "2EF3059FBFF785F4A324396C036A4322B7BEA4E8FE682C00935A3FE174F28DB6" ascii
      $s12 = "<</Length 35/Filter/FlateDecode>>" fullword ascii
      $s13 = "58%PH%})]F" fullword ascii
      $s14 = "IrFf146" fullword ascii
      $s15 = "<</Metadata 3 0 R/Pages 4 0 R/Type/Catalog>>" fullword ascii
      $s16 = "DSIt^W-" fullword ascii
      $s17 = "i[zqeG>S<" fullword ascii
      $s18 = "<</Linearized 1/L 284394/H[284156 168]/O 6/E 284324/N 1/T 284329>>" fullword ascii
      $s19 = "F785F4A324396C036A4322B7BEA4E8FE682C00935A3FE174F28DB6>>>/Prev 284324>>" fullword ascii
      $s20 = "NwBq~s9" fullword ascii
   condition:
      uint16(0) == 0x5025 and filesize < 800KB and
      all of ($s*)
}

rule PDF_Embedded_Exe : PDF
{
   meta:
      description = "file based on embedded functions"
   strings:
      $header = {25 50 44 46}
      $Launch_Action = {3C 3C 2F 53 2F 4C 61 75 6E 63 68 2F 54 79 70 65 2F 41 63 74 69 6F 6E 2F 57 69 6E 3C 3C 2F 46}
        $exe = {3C 3C 2F 45 6D 62 65 64 64 65 64 46 69 6C 65 73}
    condition:
      $header at 0 and $Launch_Action and $exe
}

rule js_wrong_version : PDF raw
{
   meta:
      author = "epicyber sec"
      description = "JavaScript was injected"
      version = "0.1"
      weight = 2
      
        strings:
                $magic = { 25 50 44 46 }
            $js = /\/JavaScript/
            $ver = /%PDF-1\.[3-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule invalid_trailer_structure : PDF raw
{
   meta:
      author = "epicybersec"
      weight = 1
      
        strings:
                $magic = { 25 50 44 46 }
            // Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}


