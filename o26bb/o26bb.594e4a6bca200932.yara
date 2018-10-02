
rule o26bb_594e4a6bca200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594e4a6bca200932"
     cluster="o26bb.594e4a6bca200932"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious filerepmalware"
     md5_hashes="['055b8b9fd6d018957194fc96cf1bcc023a3f6c19','7ba5f399c63643fa2e3aa6371ae9a503ab734bbf','e26f576172b700ddc7f9ca62e671d709c9119246']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594e4a6bca200932"

   strings:
      $hex_string = { 0bb00bb00bb00be00fd909e0172f042f042f042f042f042f042f042f043100f0175100001810182018300d31000a0230184018501821183100f0175100601870 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
