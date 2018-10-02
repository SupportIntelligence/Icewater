
rule m2319_15adb1e9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.15adb1e9ca000b32"
     cluster="m2319.15adb1e9ca000b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['25de63d3e7012f64262a01eea3b357216c9500fb','1361c98003516e9c3e5fbf6d917f1812e6b4e891','1b4bd208762e0978a1541ffa0441a10e4e2ce912']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.15adb1e9ca000b32"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
