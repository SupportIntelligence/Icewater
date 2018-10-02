
rule m2319_17b559e9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.17b559e9ca000b32"
     cluster="m2319.17b559e9ca000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script html"
     md5_hashes="['24907274a0c80d7797c0d0fbeec5d95991a2b34d','666d5e26617a94ea7396547547f8b841b552b016','91dbea4941ba5b91cd3156904932dbbee6661cb4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.17b559e9ca000b32"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
