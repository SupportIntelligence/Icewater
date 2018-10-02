
rule n231d_399a9099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.399a9099c2200b12"
     cluster="n231d.399a9099c2200b12"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker hqwar"
     md5_hashes="['de94d41bec9b0cf0a052ecb69e1c3f61ff7110df','5922be302511e1404dba0a916e45e2d89ddbe13c','c2a5189fa1d4454194f4ccfd03bac78f3a7c1236']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.399a9099c2200b12"

   strings:
      $hex_string = { 7e05d0e3ef98acfc3eb0572ba9f0c14a1da0e6670c71589cf272566b6d0b5bd4b607e02d97fdcf5cb4e743df12f54749426a7f768a25c5d5d93af7f437143541 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
