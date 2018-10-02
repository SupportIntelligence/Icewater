
rule k2319_1a1a1ab9c9000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1a1ab9c9000912"
     cluster="k2319.1a1a1ab9c9000912"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['7dda29a2c2b402d79dab21a57ff6acad31693d15','147506392ee2ad22dc8f5cb35e1e5d3a6811761b','7282d79eeb9f748c68a64585f644db05c50ee5cf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1a1ab9c9000912"

   strings:
      $hex_string = { 696e646f773b666f72287661722050367120696e205834703671297b6966285036712e6c656e6774683d3d3d282830783133322c313338293c352e363945323f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
