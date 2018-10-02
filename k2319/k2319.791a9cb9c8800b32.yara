
rule k2319_791a9cb9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.791a9cb9c8800b32"
     cluster="k2319.791a9cb9c8800b32"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['58c4c656be5c1317d7e40a2b3fe7be18752f433d','c3966ef6fd598526e0ea10dd0b3582b226591fc5','a93360484c408546e4e916f0d4f9d42c4d8cb050']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.791a9cb9c8800b32"

   strings:
      $hex_string = { 3139293a2836322c32302e354531292929627265616b7d3b766172204a3143367a3d7b27743469273a227868222c274c387a273a66756e6374696f6e28512c42 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
