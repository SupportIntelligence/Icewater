
rule m2319_1e490de1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1e490de1c2000912"
     cluster="m2319.1e490de1c2000912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script html"
     md5_hashes="['44be1f97036bd6cc16773367915dbb482312f34f','2a89400b7a667f484c5d751418a8142eace8bba4','e06f13a8df2f70cd2e551fd2d25bde877fa4c214']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1e490de1c2000912"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
