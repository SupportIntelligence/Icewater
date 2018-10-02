
rule m2319_1e4947a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1e4947a1c2000b12"
     cluster="m2319.1e4947a1c2000b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['fb99f0f2a356f4e576353f79d99dc34b4d4fcc81','67ec343dc6bafdae42a4f93033a762c1e360c89b','187979fec7a4f9a7902c23d9ee9d2a327e4a6cb1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1e4947a1c2000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
