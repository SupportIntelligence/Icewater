
rule m2319_1ec947a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1ec947a1c2000912"
     cluster="m2319.1ec947a1c2000912"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['bb243a158f7c64696543e2d431c92fd656ff19da','f69fe2609165eb638fdfcb3d0b571c8599a6a277','8f3e9a79fa3a5b91ab536da1c6488d50f1562bd5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1ec947a1c2000912"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
