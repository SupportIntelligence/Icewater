
rule n26bb_3a5c6b18d9652b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.3a5c6b18d9652b16"
     cluster="n26bb.3a5c6b18d9652b16"
     cluster_size="284"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="asvcs engine heuristic"
     md5_hashes="['56d73d8e5b4abdde241665a199c09501621d66e8','c4b0e8c583d22c4a84cfc4dfb5c1376eb5862a4a','1b8473a62714952e02ff909917cd8f92bc26b6f3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.3a5c6b18d9652b16"

   strings:
      $hex_string = { d1f8880c103bf77cc0b0015e5f5b8be55dc332c0ebf5558bec515356578bf98bf257e894d3fbff8326005933c9c745fc30000000418d50ff33db85d2783f0fb7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
