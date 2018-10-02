
rule o26d7_1899aa4b5ee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.1899aa4b5ee31912"
     cluster="o26d7.1899aa4b5ee31912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious accphish"
     md5_hashes="['d79b16bf3b3f43a5b201a6f6ed46abacafe1d484','7106a514370271c5c04a612de3e8c550e38b6312','4555b1ff06d007d8a69d263f435f6cc94564a6a5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.1899aa4b5ee31912"

   strings:
      $hex_string = { 00303132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a5f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
