
rule m2319_158db3a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.158db3a1c2000b32"
     cluster="m2319.158db3a1c2000b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery html script"
     md5_hashes="['175cfe82a49bed1d18e7699b4b82033b95a3b1ab','f458ba0b11670847ab91c56b6426425180fb932c','8d9c6d0d54f3862636f37455b652c32fada96651']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.158db3a1c2000b32"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
