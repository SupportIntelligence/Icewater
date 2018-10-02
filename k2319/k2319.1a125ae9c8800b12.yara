
rule k2319_1a125ae9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a125ae9c8800b12"
     cluster="k2319.1a125ae9c8800b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['16b007bb8e5782282141b98dbb10c5fafe4434f9','6fac4a004a139cbc081d9202819c55a7b8901f5b','790b8bd8676b45a5196d874640dd9a3e17e3535d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a125ae9c8800b12"

   strings:
      $hex_string = { 572c552c47297b696628595b475d213d3d756e646566696e6564297b72657475726e20595b475d3b7d766172206f3d282838372e333045312c312e3239354533 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
