
rule k26bb_65d53a6b8ec10b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.65d53a6b8ec10b12"
     cluster="k26bb.65d53a6b8ec10b12"
     cluster_size="461"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious aajd highconfidence"
     md5_hashes="['52a1300815edb3f4592646393b3b6399c850fca6','449f233415ce53da426e8563b5e76c01d42f8fd0','d36ac77a6865ca1ccaf78db07c4ab3aa4136f443']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.65d53a6b8ec10b12"

   strings:
      $hex_string = { d080e201f6da1bd281e22083b8edd1e833c24e75ea89048d281943004181f9000100007cd58b5424108b44240885d2f7d076238b4c240c570fb6398bf081e6ff }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
