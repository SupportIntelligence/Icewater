
rule m2319_3ed757a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3ed757a1c2000b12"
     cluster="m2319.3ed757a1c2000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script html"
     md5_hashes="['161f6d6b8be6772b8b52197b2472efd08afb03cb','c3bb665fd8145edf62922a3f6cbfd67560a7845e','836b3443856b74adf4bb66d6a0cbfaeaba7cc96f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3ed757a1c2000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
