
rule m2319_14ba1cc1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.14ba1cc1c4000932"
     cluster="m2319.14ba1cc1c4000932"
     cluster_size="184"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['136e184bcc0e2c17e7ee319429f886188b47e042','6ab3c5d3396b2ac700ac2d545dcb9791c4603348','7d765b0cd69c7b1fd3c98b5e2f32091fe339b9b2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.14ba1cc1c4000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
