
rule k2319_181e3de9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181e3de9ca000b12"
     cluster="k2319.181e3de9ca000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['311eecbe8bff7e910e8b18e4b2f1d745b26c82e4','a9cea424fdc2237526d97a9abd6f9ad35dcbac8f','2bafd46b7fa482a3da302bd7c3b54998ba491bd5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181e3de9ca000b12"

   strings:
      $hex_string = { 352e383245322c313139293a2837392c3078313234292929627265616b7d3b766172206a3762383d7b27643274273a226365222c277138273a66756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
