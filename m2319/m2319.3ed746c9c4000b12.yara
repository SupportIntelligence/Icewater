
rule m2319_3ed746c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3ed746c9c4000b12"
     cluster="m2319.3ed746c9c4000b12"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['ff521f700ab3b75282406cfdc83e5b4e7b7a70d9','f835401bfcae4aa9ab4d00a3a6ad68b3073d8ae1','7e8f2fae117260d65c1b80ecc5bedc6097da76ad']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3ed746c9c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
