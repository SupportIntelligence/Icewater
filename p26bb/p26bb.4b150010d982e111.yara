
rule p26bb_4b150010d982e111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.4b150010d982e111"
     cluster="p26bb.4b150010d982e111"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bmqjuuo tofsee backdoor"
     md5_hashes="['211b61451ebb283309c9a311ce72943095477bd6','44806d011a8b5235ea31daae4b50cd444f8c0560','e52c8450f3e071c1ce84e97ca040fa4b2ce515ca']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.4b150010d982e111"

   strings:
      $hex_string = { 16a5789827228dec58e53a91df433092d71fbed1a740b98ee6239c15b74c573149caac45745c96f901531c3702c5c19f4f5284b11005320694a34756aefab09e }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
