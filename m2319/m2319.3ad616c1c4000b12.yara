
rule m2319_3ad616c1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3ad616c1c4000b12"
     cluster="m2319.3ad616c1c4000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script html"
     md5_hashes="['b6c4f3c42a0b2e6d19c9676cb6529b54c300f085','3d4b5a2de88d846f6ba395be0f26cbd315902a15','e21d0aa52c0745c58f53225363a9d18f0d975401']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3ad616c1c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
