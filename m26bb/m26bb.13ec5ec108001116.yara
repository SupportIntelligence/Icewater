
rule m26bb_13ec5ec108001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13ec5ec108001116"
     cluster="m26bb.13ec5ec108001116"
     cluster_size="162"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious dealply"
     md5_hashes="['f5a958040dfd8cec9ab2abfa4bb177ead840634e','ac4dc82280686fe8cc5b0146a2c4bb511172a513','d7d729d5252801a331444c9665fbc2e6553722ba']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13ec5ec108001116"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
