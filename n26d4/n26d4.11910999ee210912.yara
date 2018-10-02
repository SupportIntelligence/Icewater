
rule n26d4_11910999ee210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.11910999ee210912"
     cluster="n26d4.11910999ee210912"
     cluster_size="340"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="webtoolbar heuristic high"
     md5_hashes="['f61a482514b0d95f15b769256e2d59ccdefb9936','0475dde18b71972adcb629a2a332aa59989f7df9','59432bdb2b6f563d61e3524276998e1749a72cc9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.11910999ee210912"

   strings:
      $hex_string = { c64481ef0385ff78118b551c3bd7760a8b45048d0cbf8954880885f6742f8b5c244c8a531380fa08732333c98d436439701074154183c01883f90a7cf20fb6c2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
