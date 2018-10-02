
rule o3f8_61efa92900000114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f8.61efa92900000114"
     cluster="o3f8.61efa92900000114"
     cluster_size="38"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddad androidos andr"
     md5_hashes="['f23e8dfb2db41da3b166acf259460165d9c57a3c','c87c34efc9659680c29d70d0a80efa2729b7dabd','9c218190411410c3e3c2d00717b7f5d7ed3a5b0f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o3f8.61efa92900000114"

   strings:
      $hex_string = { 6f7574206f662072616e676500083b2073656375726500563b5c732a283f3a285b612d7a412d5a302d392d2123242526272a2b2e5e5f607b7c7d7e5d2b293d28 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
