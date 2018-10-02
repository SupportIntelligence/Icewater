
rule k2319_185996b9ca800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185996b9ca800912"
     cluster="k2319.185996b9ca800912"
     cluster_size="49"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['06e7f66fa2467dc7d50c746b6ae43c2d41d90681','d4b8f3b799c97245373951c2588ac65c055a1d82','ec08b41e51c1951598b2570be74383217a2eead3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185996b9ca800912"

   strings:
      $hex_string = { 307833462c38362e354531292929627265616b7d3b7661722048324330383d7b2742324f273a362c274b3038273a66756e6374696f6e28742c57297b72657475 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
