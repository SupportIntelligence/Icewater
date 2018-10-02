
rule n3f8_4d12da1cc6a21132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.4d12da1cc6a21132"
     cluster="n3f8.4d12da1cc6a21132"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos cloud dldr"
     md5_hashes="['01fec3f6d22e701d9a2d996eaec3ca9d735197a4','4510d11e149cb3e5c3efa83665f809629c179e65','7c4f0ce91808d32cb6acfc349875f095f4c7e745']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.4d12da1cc6a21132"

   strings:
      $hex_string = { 64792f50696e673b00324c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f737064792f507573684f6273657276657224313b00304c63 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
