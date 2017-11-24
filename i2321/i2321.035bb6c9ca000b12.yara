
rule i2321_035bb6c9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.035bb6c9ca000b12"
     cluster="i2321.035bb6c9ca000b12"
     cluster_size="4"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['1347f23880eee38ecaf86b2d8ee8a908','57b8a1495a20b3e8ff2690c15e9c2747','aa7762daeec2be396a470e1b718a3467']"

   strings:
      $hex_string = { f917cbb523b5dafc4c78766b6da1d9a855eab1e4ed4ec9b146a512c23772cf549a47e7cf9d2bd76747e7ea9552383e3cfeecf0e881a7b28ec381aeaf2e9c6fcc }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
