
rule j3f8_7866a6b0393b0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7866a6b0393b0130"
     cluster="j3f8.7866a6b0393b0130"
     cluster_size="90"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos apprisk"
     md5_hashes="['909ee3950b182cbf5767f37ee6e5eca62db0b0a1','6097f639c2031de547fd67855a30d629010168e1','a83a665c8e27b07db743e8e5f2bf59698c4846f6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.7866a6b0393b0130"

   strings:
      $hex_string = { 6c76696b2f73797374656d2f446578436c6173734c6f616465723b001e4c6a6176612f696f2f42756666657265644f757470757453747265616d3b000e4c6a61 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
