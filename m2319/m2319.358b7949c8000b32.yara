
rule m2319_358b7949c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.358b7949c8000b32"
     cluster="m2319.358b7949c8000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['3388f442ecee7daf42f0719046428aecfb02dadb','8a2d7d24e8cb778d59bfbb6f7540cfc1894fbb83','d5c6e9f5e0e9824b708650076fdee58c05c07620']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.358b7949c8000b32"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
