
rule k2319_180994b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.180994b9c8800912"
     cluster="k2319.180994b9c8800912"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script kryptik diplugem"
     md5_hashes="['338cc93012e0b81414e147075e8e7caf8a254510','2cffe7d9924aa69f2f2457a11326d239590ad562','13a5fa28f38fde5d8a39cd338cfdd21f9e4f2902']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.180994b9c8800912"

   strings:
      $hex_string = { 646566696e6564297b72657475726e204e5b505d3b7d7661722075393d2828307842372c3078313638293c3d34372e3645313f28312e31353145332c30786363 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
