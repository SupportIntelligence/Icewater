
rule n26bb_13505da1ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.13505da1ca000b32"
     cluster="n26bb.13505da1ca000b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply bundler malicious"
     md5_hashes="['06a528f9e07cd63d4f16e1240276f8f63c3d075d','fb91a06c07e5781ea421db7b80aae5e94cbaa632','0ba6ec64d74b522c22656e3a9ac5af098e9d4fc8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.13505da1ca000b32"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c7410451 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
