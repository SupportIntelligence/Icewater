
rule k2319_292d16b9c9000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.292d16b9c9000b32"
     cluster="k2319.292d16b9c9000b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['109be068d4efe786dc12521e33b3de73b23c29ac','143be22152846f11c5f1c3e582274358289080a9','c8c252e45498ea8664a685b7407c8554aaf337ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.292d16b9c9000b32"

   strings:
      $hex_string = { 2e354531293f2830783235332c313139293a28307843362c35332e292929627265616b7d3b76617220563749363d7b274836273a66756e6374696f6e286e2c64 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
