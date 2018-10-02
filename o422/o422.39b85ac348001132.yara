
rule o422_39b85ac348001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o422.39b85ac348001132"
     cluster="o422.39b85ac348001132"
     cluster_size="909"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik adposhel"
     md5_hashes="['682d2399709492bc2858534201a931994a7f9c55','1e97a213e8f3ffeed0eef9d1d17e75ebffc18e07','03e4492f181ab320f44c8dc8946a094de4f80d65']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o422.39b85ac348001132"

   strings:
      $hex_string = { 3d980fad50df9ea9f0d4e1e2a199a958f0d4e1e2648bcfa4837b49eff0d4e1e2d1b0ecc6f0d4e1e247caa636c1ddccaef0d4e1e2c3bf2574f0d4e1e227bee9f9 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
