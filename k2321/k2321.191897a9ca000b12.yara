
rule k2321_191897a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.191897a9ca000b12"
     cluster="k2321.191897a9ca000b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['7bf52b8cc80679bebb964948e7d2fe48','7e979d3d6343f68a5b6fc74e4c7021a6','f561eda92ea4aaa5315ae6658bd5bd44']"

   strings:
      $hex_string = { 9c322ec8150fd91aebdfda1c5270a972680a3b605f910ab69e8d6a6d0e46266cd0492970593f2bc5e367846402b040cf2f7d1600dbb5e4e10c840d474b73b410 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
