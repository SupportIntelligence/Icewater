
rule o26bb_4562d1029b6f4932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4562d1029b6f4932"
     cluster="o26bb.4562d1029b6f4932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious asvcs engine"
     md5_hashes="['a792795de9a105ffba0c3c9479256ba09d20938f','7301e5ba9d2bb6045574d54ce8f2113c5a10fda2','f3252094af75b97d780c0f05b06c073aa9d5b5da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4562d1029b6f4932"

   strings:
      $hex_string = { d1f8880c103bf77cc0b0015e5f5b8be55dc332c0ebf5558bec515356578bf98bf257e8cfd4fbff8326005933c9c745fc30000000418d50ff33db85d2783f0fb7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
