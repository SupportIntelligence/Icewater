
rule m26c0_2696e4c9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26c0.2696e4c9c4000b14"
     cluster="m26c0.2696e4c9c4000b14"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor malicious virut"
     md5_hashes="['84358bab26fab358cf9d06ffb7452282ba89b181','cb91de15236be55e29b467434ce3c634551c3da1','a1c7074bd9ceccd38608ee038185094a5e31f61a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26c0.2696e4c9c4000b14"

   strings:
      $hex_string = { 395e28742c8b7e145357e8a6fbffff85c00f850e0a000033c08d8f0000ffff034e201346243b46347207770b3b4e30730633c05f5e5bc333c040ebf7c7461004 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
