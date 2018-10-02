
rule k2319_292d1ab9c9000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.292d1ab9c9000b32"
     cluster="k2319.292d1ab9c9000b32"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5abdca7121e9043865105ac862580bac3f6128e9','5a02a791e6aedb4d4a3cff1f109230f6c8f6a2bd','69c60a199e7942dce13d18d6a70f747ed12c11b3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.292d1ab9c9000b32"

   strings:
      $hex_string = { 2e354531293f2830783235332c313139293a28307843362c35332e292929627265616b7d3b76617220563749363d7b274836273a66756e6374696f6e286e2c64 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
