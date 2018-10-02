
rule o26bb_17d0d986ee208b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.17d0d986ee208b12"
     cluster="o26bb.17d0d986ee208b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gamehack malicious unsafe"
     md5_hashes="['ffccb179054045717f87318db0016fe4fdd0d45e','ae7106f174fcecf8c7eca1deeaeceeff894a9379','2a9a92e657ec0a169b80b0eb07ed4518f5508b1f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.17d0d986ee208b12"

   strings:
      $hex_string = { 45018bcf2bca415333dbd1e93bfa1bfff7d723f976118d6424008a0a8d5202880843403bdf72f3c6460b085beb3980f9100f85fc000000837c24180074058d55 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
