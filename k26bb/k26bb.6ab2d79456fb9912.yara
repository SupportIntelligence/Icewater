
rule k26bb_6ab2d79456fb9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6ab2d79456fb9912"
     cluster="k26bb.6ab2d79456fb9912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo malicious heuristic"
     md5_hashes="['1a87e1db51448385a6cb12e9c240af0b0b71564c','f1d3bd79cd100617a5fb32ce917fd7b492126ea9','45e674906196ca2278412d5388b200126a21ccb1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6ab2d79456fb9912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
