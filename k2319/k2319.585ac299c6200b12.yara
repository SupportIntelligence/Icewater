
rule k2319_585ac299c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.585ac299c6200b12"
     cluster="k2319.585ac299c6200b12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['627b48d777af577dada08d1e68d0f47adf049f2e','371c706efb042cda42348c8e81a6569fd32ccfee','d3a772bb3d2b6d6ab17fc768955109822bf1e22a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.585ac299c6200b12"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e2067375b535d3b7d766172206f3d2828372e3945312c30784236293c34342e3f2831302e373645322c307843 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
