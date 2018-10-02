
rule m2319_15ad19a9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.15ad19a9c8800b32"
     cluster="m2319.15ad19a9c8800b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['40f0bfcb88f67328e81c635ae61a03af5b5a4f2b','c0ec682ee5d9a6953c63eab2f74f1ac49b705b6c','b0e26eca17b0a32b435c7c87d889e44e070cc424']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.15ad19a9c8800b32"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
