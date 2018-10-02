
rule k2319_485e3949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.485e3949c8000b12"
     cluster="k2319.485e3949c8000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem script adplugin"
     md5_hashes="['98d972f6605bc402d543d70ab39f176344b26c99','4823cb474bf8f6913d3ca68b3e9d33a17769c6a4','95baa88bf8417e54ea6fe386044769e0bb32ca11']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.485e3949c8000b12"

   strings:
      $hex_string = { 273a66756e6374696f6e285a2c79297b72657475726e205a2f793b7d2c27703469273a2242227d3b6368726f6d655b28763341372e4533692b763341372e6c35 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
