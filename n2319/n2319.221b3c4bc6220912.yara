
rule n2319_221b3c4bc6220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.221b3c4bc6220912"
     cluster="n2319.221b3c4bc6220912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script faceliker clicker"
     md5_hashes="['2a55ccfa63a499af84eb8caeaa95638c30e06f00','8ed6fb80a6f767fadedbb502832b36c89163c29f','8eaa5fffe75625c9235dc7a6ff3d6afbb6e69b03']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.221b3c4bc6220912"

   strings:
      $hex_string = { 617265617c627574746f6e2f692c563d2f5c5c283f215c5c292f672c573d7b49443a6e65772052656745787028225e2328222b462b222922292c434c4153533a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
