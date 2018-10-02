
rule o26bb_4986b4cbc6210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4986b4cbc6210b32"
     cluster="o26bb.4986b4cbc6210b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious heuristic"
     md5_hashes="['8ece404a3c73c82eb154c6f15a4b1fbce55c93cb','6dfcf73e2f09256f18ad7984f7d35a220610500d','d7d1c12ec7cefb3dd9d6b3eea791e52bbe6d5cb3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4986b4cbc6210b32"

   strings:
      $hex_string = { 0bb00bb00bb00be00fd909e0172f042f042f042f042f042f042f042f043100f0175100001810182018300d31000a0230184018501821183100f0175100601870 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
