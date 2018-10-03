
rule m26bb_134aea48c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.134aea48c0000b16"
     cluster="m26bb.134aea48c0000b16"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious unwanted"
     md5_hashes="['15432431f5af836d73ad940a82ee0c5a63a60ec0','4778fa531a81e8e8b95925865f880055a305a5b4','95f7f208092a91b427d7afe306a2a865b6b3b52b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.134aea48c0000b16"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
