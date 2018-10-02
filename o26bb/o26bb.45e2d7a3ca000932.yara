
rule o26bb_45e2d7a3ca000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.45e2d7a3ca000932"
     cluster="o26bb.45e2d7a3ca000932"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="strictor malicious autoit"
     md5_hashes="['b05361c85892dd13f9410df73f05e9eac4b4f3d9','0bbad4e872aa35b07325eeddb0281914be3fcc8a','fbc5ff5cf02da8941fcb1c8205660e7a9cdae16e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.45e2d7a3ca000932"

   strings:
      $hex_string = { d1f8880c103bf77cc0b0015e5f5b8be55dc332c0ebf5558bec515356578bf98bf257e894d3fbff8326005933c9c745fc30000000418d50ff33db85d2783f0fb7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
