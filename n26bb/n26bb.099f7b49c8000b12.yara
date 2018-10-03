
rule n26bb_099f7b49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.099f7b49c8000b12"
     cluster="n26bb.099f7b49c8000b12"
     cluster_size="65"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="softonic softonicdownloader malicious"
     md5_hashes="['8bdc1627c6939822586d53230886009336212e87','da642710f848b36c74d754e1fdb4e7d4c1c39317','dfc2bc002e5ee82f42f3b5c64a7c1cdf8ee905ef']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.099f7b49c8000b12"

   strings:
      $hex_string = { 24b0157954ade7b3edc56ae18a60eb33beb55f10d5a0915699894ad14b17a467265c4e867edaaf7832f08f63b288a75e7d64efd3bf7b2fa17a182e0a3f3775e3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
