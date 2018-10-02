
rule k2319_393687b9ca800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.393687b9ca800b32"
     cluster="k2319.393687b9ca800b32"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['35fb45dd7a0c541d1e172a685d3ec4ce03fbe61a','810eb1f7ff35d5301de2d5beba68e996d24e1434','c7ea2d76f713974c43e63979463c086d62587b7d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.393687b9ca800b32"

   strings:
      $hex_string = { 66696e6564297b72657475726e207a5b4c5d3b7d766172204d3d2828307834362c3131312e394531293c30783142433f2772273a2831322e383445322c373329 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
