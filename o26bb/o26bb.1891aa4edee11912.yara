
rule o26bb_1891aa4edee11912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.1891aa4edee11912"
     cluster="o26bb.1891aa4edee11912"
     cluster_size="375"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious hacktool accphish"
     md5_hashes="['75151cba07a0bcb1acb433334e9da026ff7bb4c1','350b9dfa9fc7982af48a14140e3d41244e6130e3','72668092f3d09fd58796bf7762e4e5415840b2da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.1891aa4edee11912"

   strings:
      $hex_string = { 00303132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a5f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
