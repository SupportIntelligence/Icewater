
rule m2319_1d49a9e9ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1d49a9e9ca000912"
     cluster="m2319.1d49a9e9ca000912"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['90a061cbc7d564fd8b3962e1478fb3bd85bcc4f9','854e695edb72dfd1c60cca858594344d288eb94e','9af11ce8160f7a35534f234484c2087a954ba6b5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1d49a9e9ca000912"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
