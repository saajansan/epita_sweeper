/*
   YARA Rule Set
   Author: epicybsec
   Date: 2023-06-30
   Identifier: malware
  
*/

/* Rule Set ----------------------------------------------------------------- */

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
      8 of them
}

