
rule m2319_16bb1cc1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.16bb1cc1c4000932"
     cluster="m2319.16bb1cc1c4000932"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['4e0ac64d19edec01d399b2c2c3405ba8edc7bcb6','a1e10386a2c6c5e7cd5d376b4bcc3e702c7f4035','9277287458165a0f65e24c16e0554d82290e0a8b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.16bb1cc1c4000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
