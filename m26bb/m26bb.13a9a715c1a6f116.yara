
rule m26bb_13a9a715c1a6f116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13a9a715c1a6f116"
     cluster="m26bb.13a9a715c1a6f116"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious ccmw"
     md5_hashes="['7609afb72256d637a8d9b17255307f04e88b633d','b3d978974077d230a0756574b81f6975ae496ab3','e637550555865aa8a4ba29788e9398bf5f9d6bc4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13a9a715c1a6f116"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
