
rule k2319_594edec1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.594edec1c8000912"
     cluster="k2319.594edec1c8000912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem script asmalwsc"
     md5_hashes="['0f848c0c81047061aa48bd218f69fc63e87f9f61','8a6f7a43d56a1abe0429d06bd69def98123e6e55','931b2a58488fb981c7ba15ef2fae266580867cf9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.594edec1c8000912"

   strings:
      $hex_string = { 73696f222c27413535273a22656d222c27783630273a66756e6374696f6e2861297b77696e646f775b282828342e303545322c313230293c3d307842313f2837 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
