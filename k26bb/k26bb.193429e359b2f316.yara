
rule k26bb_193429e359b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.193429e359b2f316"
     cluster="k26bb.193429e359b2f316"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious dealply"
     md5_hashes="['33bf3e997e75fbd6e8612a3f1280f926a190be74','cf0b585ad5f25d42a8e7c4ce1bf16e3412d94efc','3fe0c39cddd14193324f9bfa0247b961d7f48a2c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.193429e359b2f316"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
