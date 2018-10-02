
rule k2319_1a1194b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1194b9ca800b12"
     cluster="k2319.1a1194b9ca800b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['7854e6b25e3bfc16be14b47d2e27a2a2631868ab','7ea00196c8cc515314c8cc6936876870ef8f5b9e','380b68c45d5b29d7fb30f7ccc3b3e0c134a8d0a9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1194b9ca800b12"

   strings:
      $hex_string = { 783141302c313139293a28392e353845322c31322e3730304532292929627265616b7d3b766172205a377a36483d7b274d3648273a66756e6374696f6e28772c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
