
rule m2319_3b506a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b506a49c0000b12"
     cluster="m2319.3b506a49c0000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['7b80386b42da9eb197328ff8d84427868fa72874','ff1e96c466dd0389878179bc5c18f42f023d8dda','4f28b4c6e0c9ad36c725dfd9a755d6c7b7603416']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3b506a49c0000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
