
rule j3f8_7866b6b0189b0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7866b6b0189b0130"
     cluster="j3f8.7866b6b0189b0130"
     cluster_size="174"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos origin"
     md5_hashes="['8b5787f107cb721eafeb109bc8b67753ecbc0ec6','5d042391e991dba3e9b25954ffdce1da9cb8d93d','3eb4149a5559f0b83db3ffa745ef39d16c4cb686']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.7866b6b0189b0130"

   strings:
      $hex_string = { 616c76696b2f73797374656d2f446578436c6173734c6f616465723b001e4c6a6176612f696f2f42756666657265644f757470757453747265616d3b000e4c6a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
