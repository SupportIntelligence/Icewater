
rule j26bf_18d66cdcc2210b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.18d66cdcc2210b30"
     cluster="j26bf.18d66cdcc2210b30"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo malicious heuristic"
     md5_hashes="['da1681d37eff92876f537f5f556d2498da78d8d8','1668ca107152fd45b795b3ecaf9d477fac38038f','5ac283135ad1e5bb9ea1a636fa46b02531f3ea76']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.18d66cdcc2210b30"

   strings:
      $hex_string = { 747269627574650053797374656d2e52756e74696d652e496e7465726f70536572766963657300436f6d56697369626c65417474726962757465004775696441 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
