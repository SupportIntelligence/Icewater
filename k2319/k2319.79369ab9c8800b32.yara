
rule k2319_79369ab9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.79369ab9c8800b32"
     cluster="k2319.79369ab9c8800b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4e9cc4d405eeb78a2e6ed50d3e9046bd1bbe5649','07230fcf733a65355d452863afb5dc580fa39246','238bec00fc9bfbb739c4f8ca33d11ba2d219cb91']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.79369ab9c8800b32"

   strings:
      $hex_string = { 384533293f2836372c322e32394532293a2830783133422c37322e292929627265616b7d3b7661722076366c37683d7b27553068273a66756e6374696f6e2847 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
