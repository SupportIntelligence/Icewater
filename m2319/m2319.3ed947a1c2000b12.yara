
rule m2319_3ed947a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3ed947a1c2000b12"
     cluster="m2319.3ed947a1c2000b12"
     cluster_size="133"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['2c2ed795646844b14f11a539c69b6fd28f401ec9','0e2f0a870938028325796fa317daacb23c6d0f2e','99fd2be02c0805e2af791aa34e22bb2d3720cb8e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3ed947a1c2000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
