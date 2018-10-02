
rule k2319_391294b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391294b9ca800b12"
     cluster="k2319.391294b9ca800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['342c00ea1c904544dc86cc5da7ed825e31fc22a4','477eb77c8c0fcbec1249d146fb60a6d6bb9f0b79','cd662615b897b56433059c120ff84d737f8f4962']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391294b9ca800b12"

   strings:
      $hex_string = { 3d756e646566696e6564297b72657475726e20445b655d3b7d76617220503d282830783141442c342e36324532293e2830783131312c38322e293f2833352e37 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
