
rule m3e7_1356535cc2210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.1356535cc2210b32"
     cluster="m3e7.1356535cc2210b32"
     cluster_size="143"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun backdoor ludbaruma"
     md5_hashes="['0545514245eed689bc8cdc22e992478c','063504cd2f8d21addad948f310d4bae8','2073fa0d1449e5369b4c8a6966183626']"

   strings:
      $hex_string = { 8d34e58c30e48a2de48729e38526e28221e2801fe17d1cdf7918de7615dd7314dc7011db6d0fda6a0dd9680bd86508d86208d76007d65e06d55c05d35904d157 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
