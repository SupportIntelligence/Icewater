
rule j3f8_5846b6b01abb0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5846b6b01abb0130"
     cluster="j3f8.5846b6b01abb0130"
     cluster_size="162"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos apprisk"
     md5_hashes="['b2989a36b50cba7d4eac83369f774dc141e09720','289fa6c72a65dc1d2e585019b82363d4d2876248','5dda1b4ccfa6310d79a6d66d43ab9bcdf76a1fc7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5846b6b01abb0130"

   strings:
      $hex_string = { 6c76696b2f73797374656d2f446578436c6173734c6f616465723b001e4c6a6176612f696f2f42756666657265644f757470757453747265616d3b000e4c6a61 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
