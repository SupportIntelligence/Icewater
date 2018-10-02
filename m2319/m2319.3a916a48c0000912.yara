
rule m2319_3a916a48c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3a916a48c0000912"
     cluster="m2319.3a916a48c0000912"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['1b2a748f34ca0044be937a86bba567c071796bb7','d2252c0a0d22a7dbab42f518dc8206ed8d6d57fc','e429934e2f236c065c5550402f8824b960f3cc9b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3a916a48c0000912"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
