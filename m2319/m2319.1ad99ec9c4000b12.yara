
rule m2319_1ad99ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1ad99ec9c4000b12"
     cluster="m2319.1ad99ec9c4000b12"
     cluster_size="110"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['a89ee7df99194c78d2cadc7e7ca7b2914e4f5fdb','f390ae3d2748e461fcb38270578295841cf7573d','84a86bcd624bb9cb971d8d394704eaffab4ddd96']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1ad99ec9c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
