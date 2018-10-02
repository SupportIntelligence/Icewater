
rule k26bb_193c21e159b2e316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.193c21e159b2e316"
     cluster="k26bb.193c21e159b2e316"
     cluster_size="40"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore unwanted dealply"
     md5_hashes="['8c2e4725172850ed6b670c85724cc94aa83d1b8e','0fc43c106d4da1f249d3d41c8714e79d51d3f8fc','ba3132084da307b8331e9659b33e2709fb60830a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.193c21e159b2e316"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
