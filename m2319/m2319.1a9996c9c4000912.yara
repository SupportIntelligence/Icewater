
rule m2319_1a9996c9c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1a9996c9c4000912"
     cluster="m2319.1a9996c9c4000912"
     cluster_size="415"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['5d5aaeb0ebbdc2aaf0943a769de5e3b9788864e2','6163f6b3ec9fe9eb52ecd7a6e6d3f6507ba5c592','779d9f0bc88b26455ed35ef621aafa4a5efaa4cd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1a9996c9c4000912"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
