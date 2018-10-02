
rule j3f8_5866a6b0393b0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5866a6b0393b0130"
     cluster="j3f8.5866a6b0393b0130"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos origin"
     md5_hashes="['d76cd7fb8971b5ea8d3b65240ba806ca6fe665fd','d5008b7dd1e0b3680f35ce531348dcea98b38328','614a618635c1c3f15b0e1cfc60f2c3fbcfbc917b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5866a6b0393b0130"

   strings:
      $hex_string = { 616c76696b2f73797374656d2f446578436c6173734c6f616465723b001e4c6a6176612f696f2f42756666657265644f757470757453747265616d3b000e4c6a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
