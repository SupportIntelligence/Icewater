
rule k2319_594fdec1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.594fdec1c8000912"
     cluster="k2319.594fdec1c8000912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem plugin script"
     md5_hashes="['ffef4a14eb6d2a5878fe739bb1b4b75de744195e','4b5328ff4c3cdf54035f6d079bc6c46c9e176d94','efdd3fe5b4a5cccda379c13d33d22a87569039e5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.594fdec1c8000912"

   strings:
      $hex_string = { 73696f222c27413535273a22656d222c27783630273a66756e6374696f6e2861297b77696e646f775b282828342e303545322c313230293c3d307842313f2837 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
