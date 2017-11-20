
rule m2321_631e16c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.631e16c9cc000b16"
     cluster="m2321.631e16c9cc000b16"
     cluster_size="156"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00306130f80323f67a782ee789c2cf2e','012b7b3692ce2d17526fa9baa183fd2d','11e4d3321b41b38d8c5d2b4155625d17']"

   strings:
      $hex_string = { 408a61082a066fa7a7e9e1b158d38943fb4c509f05d8203ba22f57363a7e0f92228d4dce170aa6ef78555a47e6b37104f498e2b25cabd8269793cb1ff51bc7bc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
