
rule k26bb_409048b4ee208912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.409048b4ee208912"
     cluster="k26bb.409048b4ee208912"
     cluster_size="368"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="attribute filerepmalware heuristic"
     md5_hashes="['dc11a04901c316d8ff4c5801ab42da48fc8e2468','043a9e04c6f919a2817c28b1bf09a688b960ab9e','4417216498bd3f3cb0f8aed7f6a9a79cdc6d4fdf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.409048b4ee208912"

   strings:
      $hex_string = { d07e718b75f88d45f36a0150ff75d0e8cb36000085c0745f395de47521807d0b0d742b807d0b0a74258a45f388043e463ac388450b74403b75f47ccaeb390fb6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
