
rule m2319_14b21ec9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.14b21ec9c4000932"
     cluster="m2319.14b21ec9c4000932"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['56a1373c5712a059744ef24723ab68a1f42edb13','e9e702c218965c038a82eeeb90cc343760dca089','6a9654e3079bc0a07e5c886d929fa0029b66d2c6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.14b21ec9c4000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
