
rule o422_31b85ac348001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o422.31b85ac348001132"
     cluster="o422.31b85ac348001132"
     cluster_size="910"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik adposhel"
     md5_hashes="['739115bcb91c62b11154cca4f28beb65d6cadff2','11b924d1e6a191e238be279b1596a32356a222c5','2cf7c098d72730cdb327dc410cdadf72f7110a17']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o422.31b85ac348001132"

   strings:
      $hex_string = { 3d980fad50df9ea9f0d4e1e2a199a958f0d4e1e2648bcfa4837b49eff0d4e1e2d1b0ecc6f0d4e1e247caa636c1ddccaef0d4e1e2c3bf2574f0d4e1e227bee9f9 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
