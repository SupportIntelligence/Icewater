
rule m26bb_13a3260f913b7116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13a3260f913b7116"
     cluster="m26bb.13a3260f913b7116"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious ccng"
     md5_hashes="['50f34afa03697c8719d8aca11080d4ded9d941b4','555819952d10a00dbea33f5b071249b46912a6a8','f8420dc45ac25d629fc1f9ef22be2a3dba4a5344']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13a3260f913b7116"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
