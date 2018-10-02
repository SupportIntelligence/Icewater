
rule n26c9_331495a1c2000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c9.331495a1c2000b16"
     cluster="n26c9.331495a1c2000b16"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="expiro malicious badfile"
     md5_hashes="['cb394991c595171a67cf5ab37e190a443f8aeb85','6a78f4fc618c7b16ab0a63a28e93733e1bf2af24','d4b1fcf60d86164c52bc74bfcc9ec37a36dce3e1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c9.331495a1c2000b16"

   strings:
      $hex_string = { 3a9ded59fb992ef7ae72f11f28b61712ccc46cb2d05c4a6da73c8b6f5ff5e589430e7be4ba65cb1ee15575b9778ec9711a6202ab46b31b113333ad00d1d297bc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
