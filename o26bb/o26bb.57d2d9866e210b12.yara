
rule o26bb_57d2d9866e210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.57d2d9866e210b12"
     cluster="o26bb.57d2d9866e210b12"
     cluster_size="196"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious unsafe unwanted"
     md5_hashes="['40ba913919cc1ea7de40d8168c21cb841179c9c5','00f9411972c7d5483ce6dd11048a7bf3a3b20947','e0be64962183ad3e2885c0dc9cb7c3869516dd2e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.57d2d9866e210b12"

   strings:
      $hex_string = { 45018bcf2bca415333dbd1e93bfa1bfff7d723f976118d6424008a0a8d5202880843403bdf72f3c6460b085beb3980f9100f85fc000000837c24180074058d55 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
