
rule m2319_3ad297d1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3ad297d1c4000b12"
     cluster="m2319.3ad297d1c4000b12"
     cluster_size="89"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['ac32ccf6e822f7b16cfe7b8794136393a51d8c62','5af3d5a6c9410b81a77f3d16a29ff399b0286c8d','a668f14b1e5ca9566b254a5301df0bf45f218ab1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3ad297d1c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
