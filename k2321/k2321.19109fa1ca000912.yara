
rule k2321_19109fa1ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.19109fa1ca000912"
     cluster="k2321.19109fa1ca000912"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['00da722d3d865b21b33a8c58fa16e12c','1bf79ec48012310ecab9e8e6fd89ac4e','f69be19219d2b1c0cad9140d5dce24f0']"

   strings:
      $hex_string = { 1b3f88f6633e429fa7b8282ee1aa261679ad0740c666eba9587fec7409eeb714abfddd003b8dc4d47e198b4850755870765567237cd0029310bf35d3ed77b0ea }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
