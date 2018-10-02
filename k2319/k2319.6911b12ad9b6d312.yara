
rule k2319_6911b12ad9b6d312
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6911b12ad9b6d312"
     cluster="k2319.6911b12ad9b6d312"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector exploit html"
     md5_hashes="['7506257790b218537f72ddbcbb3edb0be25c73b2','69580bb027782814274d7af7e84797bdef2f505f','ef2a4348011f0c84fa1acd56da1d78fe3567bd9d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6911b12ad9b6d312"

   strings:
      $hex_string = { 297d3b766172206b623d6465636f64655552492822253733637269707422292c6c623d2f5e5b2d2b5f302d395c2f412d5a612d7a5d2b3d7b302c327d242f2c6d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
