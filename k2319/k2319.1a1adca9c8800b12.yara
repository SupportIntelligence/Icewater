
rule k2319_1a1adca9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1adca9c8800b12"
     cluster="k2319.1a1adca9c8800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['602a655f5389c017e4df9fa809cff2f8acd4e268','778c05a53869dfc7c331dae2a54db2761a8843fb','bb6f5ac0b6b269c0c3f38b6100ac4c7d6ae29b01']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1adca9c8800b12"

   strings:
      $hex_string = { 3e312e353545323f2830783141312c313139293a2830783141412c3133362e304531292929627265616b7d3b76617220533762374e3d7b2759384a273a22636f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
