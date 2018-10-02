
rule m2319_350b5cc1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.350b5cc1c4000b32"
     cluster="m2319.350b5cc1c4000b32"
     cluster_size="107"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['e26ec986fb88138a98be260c2b2f1f0e46949742','daa6ea0b59752f9914b6025fe273d04f7ebc3b31','84245c99a78988580e0383c807dec819fb7aa7c6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.350b5cc1c4000b32"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
