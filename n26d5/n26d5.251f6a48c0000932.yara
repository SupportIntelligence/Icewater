
rule n26d5_251f6a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.251f6a48c0000932"
     cluster="n26d5.251f6a48c0000932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['1aff56b16d02891b733061e31f2a6577148ec8e5','987829124ca1bdb6c64ff3d761f3b8b442586fdf','f0452e2bbaa42cb11b30a4dcea2d0b40c73bace5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.251f6a48c0000932"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
