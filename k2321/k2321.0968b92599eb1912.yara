
rule k2321_0968b92599eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0968b92599eb1912"
     cluster="k2321.0968b92599eb1912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['0d18e25e6d857e3efacc3ad37756778b','81f6cd790f5034960a8b0a287d072e43','c47fdf5299f7115801f122e465ac7ee5']"

   strings:
      $hex_string = { d183a482a5bd16558b60abcadb91c362b771241e4642fce7ed4388ffb0417ade6efa728af80fb3c73c330c905ed768ceb9e993b5aec91c3d1b322550de9b1103 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
