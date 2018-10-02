
rule o26d4_3b1b11e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.3b1b11e9c8800b32"
     cluster="o26d4.3b1b11e9c8800b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious heuristic"
     md5_hashes="['f122e5c5cb2c947ef32615997f249b1b0db6df52','ea57d899db38a3ea2e7af7ac2285c479cc17eb22','974bcaf05154e4c7f79e23cd946941ece39e27b9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.3b1b11e9c8800b32"

   strings:
      $hex_string = { 00dc4400105a040000ec44001065040000fc4400106b0400000c4500106c0400001c4500108104000028450010010800003445001004080000bc1f0010070800 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
