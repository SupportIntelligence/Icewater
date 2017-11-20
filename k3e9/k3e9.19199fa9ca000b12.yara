
rule k3e9_19199fa9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.19199fa9ca000b12"
     cluster="k3e9.19199fa9ca000b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['5fb351a4380f4693a46d3011b6e4f86b','93878d0bb44e69cd1c1719eec1755e9b','bf91b174a0f5ca7563e85153daab449b']"

   strings:
      $hex_string = { 9c322ec8150fd91aebdfda1c5270a972680a3b605f910ab69e8d6a6d0e46266cd0492970593f2bc5e367846402b040cf2f7d1600dbb5e4e10c840d474b73b410 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
