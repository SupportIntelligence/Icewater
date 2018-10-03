
rule m26bb_13a6bec144000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13a6bec144000916"
     cluster="m26bb.13a6bec144000916"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore dealply malicious"
     md5_hashes="['b6a8043fe1bb151c258ffb0b95a598b2d0f9a8a5','9cf7a8c1957e6b9681488a703202b3f069fd2763','85a4d82f1ea0749af3c6df7d382b1133929d01bc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13a6bec144000916"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
