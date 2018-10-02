
rule m2319_3d567ac1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3d567ac1c8000b32"
     cluster="m2319.3d567ac1c8000b32"
     cluster_size="213"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['e570ae615766967a54ca839f8f8ec0bc83253ccb','90c39e87a144aaa97cbe7ff39173ce0726d2d003','b8f3db93206df48217a02b3262da0e12641363f0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3d567ac1c8000b32"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
