
rule o26bb_594a4ecbc6620932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594a4ecbc6620932"
     cluster="o26bb.594a4ecbc6620932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply heuristic malicious"
     md5_hashes="['d4cea8d9f9dd8bce0912b8c814b005c637e37844','e040c105725ef80ffc89ed32c29c654f00b7ad0d','db86cb2600347dda7217226cd4860822ef857d84']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594a4ecbc6620932"

   strings:
      $hex_string = { 0bb00bb00bb00be00fd909e0172f042f042f042f042f042f042f042f043100f0175100001810182018300d31000a0230184018501821183100f0175100601870 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
