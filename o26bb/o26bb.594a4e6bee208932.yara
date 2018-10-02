
rule o26bb_594a4e6bee208932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594a4e6bee208932"
     cluster="o26bb.594a4e6bee208932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious heuristic"
     md5_hashes="['35a8de0d3790ce57e1992a863650149658142e3e','c019db5023e86a1a9dfd7a50bba3bc5dd8e8e5ac','4b5e7edf0c2800d68274443a648366b5af50f9c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594a4e6bee208932"

   strings:
      $hex_string = { 0bb00bb00bb00be00fd909e0172f042f042f042f042f042f042f042f043100f0175100001810182018300d31000a0230184018501821183100f0175100601870 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
