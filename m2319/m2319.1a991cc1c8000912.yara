
rule m2319_1a991cc1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1a991cc1c8000912"
     cluster="m2319.1a991cc1c8000912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['37679b9a7a371ca25d16895552a0869a717c4c40','610978f1057372dd9cfb1a63ff9efc1f37ee9693','e1254e91a3fc7bc570792750c180463305669846']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1a991cc1c8000912"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
