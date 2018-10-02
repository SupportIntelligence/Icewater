
rule j3f8_5846b29418bb0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5846b29418bb0130"
     cluster="j3f8.5846b29418bb0130"
     cluster_size="193"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos shedun genbl"
     md5_hashes="['b1bdc87b1b1733f8be76b606b2353aa4d775efc6','b449e7261d55b8e5647c8179dba58c9c8df31d99','0058112791b097eb5f5cd5295caa3c093b764924']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5846b29418bb0130"

   strings:
      $hex_string = { 6c76696b2f73797374656d2f446578436c6173734c6f616465723b001e4c6a6176612f696f2f42756666657265644f757470757453747265616d3b000e4c6a61 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
