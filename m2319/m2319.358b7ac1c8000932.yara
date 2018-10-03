
rule m2319_358b7ac1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.358b7ac1c8000932"
     cluster="m2319.358b7ac1c8000932"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['461f4cef928004086c84114c2cd087a178d9d8c3','5ebb4749f5f71c1bbda38f0f7f0f808e16b9f32f','a4f62debace9a61c185f3fef6a0af2e3447ea79f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.358b7ac1c8000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
