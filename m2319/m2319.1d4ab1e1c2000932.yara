
rule m2319_1d4ab1e1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1d4ab1e1c2000932"
     cluster="m2319.1d4ab1e1c2000932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script html"
     md5_hashes="['85891a8891251d68ef78a8eb97f0af13c856114f','5b07aa4f5f2f9dc6e2774494ef0d98d849d36461','933aa237181802b35fc21e8dfbe4ab8d0f344c3f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1d4ab1e1c2000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
