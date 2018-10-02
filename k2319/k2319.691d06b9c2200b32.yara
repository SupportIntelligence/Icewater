
rule k2319_691d06b9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.691d06b9c2200b32"
     cluster="k2319.691d06b9c2200b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6b184d9e8faff36224cd3266a803cec1ac2f0838','c5e1a1ecaf04b7fcab3d7c7c0605b6fab671a3e7','15e8e6f93416c0aea6ae3654d8a608f3623e46ed']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.691d06b9c2200b32"

   strings:
      $hex_string = { 362e3045312c36352e384531292929627265616b7d3b766172206c374439713d7b27483935273a342c27633171273a66756e6374696f6e284d2c4f297b726574 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
