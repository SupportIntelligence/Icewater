
rule i26c0_69bd33a9c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26c0.69bd33a9c2000b12"
     cluster="i26c0.69bd33a9c2000b12"
     cluster_size="734"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy malicious rogue"
     md5_hashes="['2eb767b2c6101eb1203d2f6c2998a1d0a64c85cb','2401033797199c3550466caabf9e45d4dece723f','9a202b919550e2d040fb88e26b48e8ac08ec3168']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26c0.69bd33a9c2000b12"

   strings:
      $hex_string = { 43726561746546696c654100000047657446696c6553697a650000004765744d6f64756c6546696c654e616d65410000000047657450726f6365737348656170 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
