
rule m26d7_0b14994f9efb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d7.0b14994f9efb1912"
     cluster="m26d7.0b14994f9efb1912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['e397f10dc4dd3bc96ce13c1b89e1f44d4f6099a5','39b74203d31ff6c0baeee7790346d9b025eed911','a5c5f4c5f72e35969b54714e5d66fcb7b52bad50']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d7.0b14994f9efb1912"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
