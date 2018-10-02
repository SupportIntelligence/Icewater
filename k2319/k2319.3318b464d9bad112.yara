
rule k2319_3318b464d9bad112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3318b464d9bad112"
     cluster="k2319.3318b464d9bad112"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector exploit redir"
     md5_hashes="['0f635bb6ae75a15b8be5158c9730e564a7c22cc8','c5e9d02bdaefadd4725a050bb0d7977857249b98','876bf86122303cc6d92b541606d287d4b167f388']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3318b464d9bad112"

   strings:
      $hex_string = { 297d3b766172206b623d6465636f64655552492822253733637269707422292c6c623d2f5e5b2d2b5f302d395c2f412d5a612d7a5d2b3d7b302c327d242f2c6d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
