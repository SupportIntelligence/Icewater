
rule m2319_3ad617e9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3ad617e9c4000b12"
     cluster="m2319.3ad617e9c4000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['06f256a455cdc6a22c3a832fb329053c151bf0fe','3938995ba6b32de1d222fdc64ff08f24ce1eb352','8467ab6a126b5230c5bb16dd3e06fa2476b879ee']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3ad617e9c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
