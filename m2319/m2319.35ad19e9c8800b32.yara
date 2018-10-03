
rule m2319_35ad19e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.35ad19e9c8800b32"
     cluster="m2319.35ad19e9c8800b32"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['3d3ce1c9bc4af7ab30a2849d1ebb6ef22c527911','b9d1298b1d24460f6683014f3f2be1b9b2adb910','37934dfc5571b20f48e34bd62c0a590b2288ee88']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.35ad19e9c8800b32"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
