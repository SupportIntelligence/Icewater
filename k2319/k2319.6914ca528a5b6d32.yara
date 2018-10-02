
rule k2319_6914ca528a5b6d32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6914ca528a5b6d32"
     cluster="k2319.6914ca528a5b6d32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script mnbfoky"
     md5_hashes="['be0bf5fa4fe251e0daf85c1958f9ad806f89e8ee','e46e9213288f044844efe328202aba2231ab18a0','9fb59f8d33dd13fdabfbf3d8365f3de38b46e1b6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6914ca528a5b6d32"

   strings:
      $hex_string = { 66696e6564297b72657475726e20465b765d3b7d766172204a3d2828307834352c3836293c3d312e33373745333f28307844362c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
