
rule k2319_691ab199c6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.691ab199c6220b32"
     cluster="k2319.691ab199c6220b32"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script crypt"
     md5_hashes="['454b619e4b06d0b8c3a3f3f8513caec5bc02ef56','f438c9c345b7b92cbcd9d029d12100b472099cf1','d5d6c6b89fba406fc1f26600e679d78b1265d7eb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.691ab199c6220b32"

   strings:
      $hex_string = { 31332e313445322c30783735292929627265616b7d3b766172204e375936783d7b277a3067273a2866756e6374696f6e28297b766172204f3d66756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
