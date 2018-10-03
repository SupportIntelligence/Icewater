
rule n26bb_529b93a9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.529b93a9c8800912"
     cluster="n26bb.529b93a9c8800912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious adwaredealply"
     md5_hashes="['5f8f475a77621895b7875086d756d893c97317a8','e411e80c984484b849b988a1ee6d0cd030e8cfdb','33f6d35446d71573d898712c9b77a914cf0a13f0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.529b93a9c8800912"

   strings:
      $hex_string = { eb145589d589d8035c2e0289f2e84fffffff4f7ff05d5f5e5bc38d4000b901000000e966ffffffc39031c9538a4a01565789c38d740a0a8b7c0a068b168b4604 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
