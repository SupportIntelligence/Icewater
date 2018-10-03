
rule o26bb_33892949c0000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.33892949c0000916"
     cluster="o26bb.33892949c0000916"
     cluster_size="45"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadsponsor malicious unwanted"
     md5_hashes="['1ac8a6527db6cc9f66804e308faf692f9b56b3a4','78130e3df7ce9a5b1c5600f7e4198c9823a01c8a','3d6fc4e3850eb374f32bc865f457f699287906ea']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.33892949c0000916"

   strings:
      $hex_string = { 243eee8ff2d05d39f14c618a802eae1b2b2d254dc8a767a433591cbae19f87f81f07fe751e06419c780e9fc313458489a68ccb4b10b59bc7e60ab8693c3a97f7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
