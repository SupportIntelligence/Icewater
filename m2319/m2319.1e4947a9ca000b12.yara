
rule m2319_1e4947a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1e4947a9ca000b12"
     cluster="m2319.1e4947a9ca000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['8141907143b5c2b24e2515e11ff78c1b5e40ba35','b8c7ca7f7f919418373a6d274f09dc536a577ab7','1b5a72d53df0b25ce369f773302da5ce98e22fdc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1e4947a9ca000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
