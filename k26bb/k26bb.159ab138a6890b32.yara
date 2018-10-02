
rule k26bb_159ab138a6890b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.159ab138a6890b32"
     cluster="k26bb.159ab138a6890b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="syddld dlder malicious"
     md5_hashes="['29ebca45ba97f10ba6d00c613d540e0c7cfeb419','ee35a106b84b424a4d95acfde6ed0daf236c654e','0121c27173f89096a9b1d834a4f393efc0ac478c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.159ab138a6890b32"

   strings:
      $hex_string = { 36332e3139372e36302f00000000687474703a2f2f39322e36332e3139372e3131322f000000687474703a2f2f73726f67686f7366756f6568666f6165667561 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
