
rule m26bb_434e7b29c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.434e7b29c8800912"
     cluster="m26bb.434e7b29c8800912"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="amonetize netfilter bicololo"
     md5_hashes="['2d2bba4e6b35f33b77e6de8ddd2ff6efbcaacc3f','8e5c00ec21f43d03e8988ae87d4d7a3aaa6c232c','4e6374d0aeaf13a2e15419a5b6397d1834129716']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.434e7b29c8800912"

   strings:
      $hex_string = { 593bc776198b06803c383d751157ff750850e80f38000083c40c85c0740f83c6048b0685c075d333c05f5e5dc38b068d443801ebf46a0c68606e4100e8950e00 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
