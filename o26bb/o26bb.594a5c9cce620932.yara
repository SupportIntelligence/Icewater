
rule o26bb_594a5c9cce620932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594a5c9cce620932"
     cluster="o26bb.594a5c9cce620932"
     cluster_size="135"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious bundler"
     md5_hashes="['71963c1321964f7a2ca4ceb76333a1841765d2c6','8527142229cac05f2b7daf20a58ede7c338dd465','3e66e9a3cd9e5a19f5c6009155e9344044bfa5f2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594a5c9cce620932"

   strings:
      $hex_string = { 0bb00bb00bb00be00fd909e0172f042f042f042f042f042f042f042f043100f0175100001810182018300d31000a0230184018501821183100f0175100601870 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
