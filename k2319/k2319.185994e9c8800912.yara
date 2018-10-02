
rule k2319_185994e9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185994e9c8800912"
     cluster="k2319.185994e9c8800912"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['790b8d39239df4e95b5e495ad270f5920d435477','0d6945ed0baed936423d05abba9c12014d036b45','171ff2df373d963c83fa7be6bd85c4ea33bd24b2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185994e9c8800912"

   strings:
      $hex_string = { 3a28307833462c38362e354531292929627265616b7d3b7661722048324330383d7b2742324f273a362c274b3038273a66756e6374696f6e28742c57297b7265 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
