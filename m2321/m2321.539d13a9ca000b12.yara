
rule m2321_539d13a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.539d13a9ca000b12"
     cluster="m2321.539d13a9ca000b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['39d2872cbe17d94e57dd8b5d8f21b57e','8bed111b945662c79345c800c5694f3d','daa918764082d831a6d4b288af1da351']"

   strings:
      $hex_string = { 0868520a592f9244fac8cbe8cdc543554ff4d89d6ae7a7933b88ab57b56c56edff649fef2b8bccf0a92c1295c4731e4b9eef193a963cbf4210cee1dfe9e68d27 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
