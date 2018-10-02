
rule k2319_1a1496b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1496b9ca800b12"
     cluster="k2319.1a1496b9ca800b12"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d2424980fb832846bc3ea27f7be3606c1136b0e0','ef8bc4d22b18397a78e8362b201438e197c40136','f2ca8012e17bdfe9e07a1c9d0c366c4d0c0b0693']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1496b9ca800b12"

   strings:
      $hex_string = { 515d213d3d756e646566696e6564297b72657475726e20545b515d3b7d766172206a3d2839333c3d2835362c3078313646293f283130352e2c30786363396532 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
