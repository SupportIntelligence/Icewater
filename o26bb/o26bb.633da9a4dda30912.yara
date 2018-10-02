
rule o26bb_633da9a4dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.633da9a4dda30912"
     cluster="o26bb.633da9a4dda30912"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious adload"
     md5_hashes="['e4a81af1722af30747b5c97afc4dacb8623a0863','b74ab614ae5218ff77fdab01e9bd6b41d1c27080','a4c344c1114220971c55e1e80de2e6f525ce3524']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.633da9a4dda30912"

   strings:
      $hex_string = { 45464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a5d000000253032643a253032643a2530 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
