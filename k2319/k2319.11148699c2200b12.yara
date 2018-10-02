
rule k2319_11148699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.11148699c2200b12"
     cluster="k2319.11148699c2200b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['3066f5ea557145ee6279ee6371b4002becf3d1c2','74b839cef2cd967520b23c440470c7195933c0f8','0a6a817dbd5654f15a33bab5881ebbb6d2a07580']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.11148699c2200b12"

   strings:
      $hex_string = { 36394532292929627265616b7d3b666f7228766172204a386820696e204735453868297b6966284a38682e6c656e6774683d3d3d2834333c283130372e2c3078 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
