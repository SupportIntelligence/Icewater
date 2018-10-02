
rule j3f8_7994d6c348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7994d6c348000330"
     cluster="j3f8.7994d6c348000330"
     cluster_size="1286"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos risktool"
     md5_hashes="['919cd3de1fe4e03c6972580ed47328e98531c52c','4eb4b92c301954adbef4d7a58c0124b477b26b5c','2e0e97ea37adb2bf59165280dc2f8adbb27a9921']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.7994d6c348000330"

   strings:
      $hex_string = { 6c76696b2f73797374656d2f446578436c6173734c6f616465723b001e4c6a6176612f696f2f42756666657265644f757470757453747265616d3b000e4c6a61 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
