
rule n26bb_13a63cc14c000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.13a63cc14c000932"
     cluster="n26bb.13a63cc14c000932"
     cluster_size="264"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom malicious"
     md5_hashes="['256514be65b8c4762dc886209b4736a48646c8ea','4b90c2253c1ed52bce5a1d6ca0fa0bab61a22253','1aebfeb70332e9117d5426f87fbe24dd88837973']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.13a63cc14c000932"

   strings:
      $hex_string = { 4df051575056e8d887000083c41085c07405c60300eb558b45f4483945fc0f9cc183f8fc7c2a3bc77d2684c9740a8a064684c075f98846feff75288d45f06a01 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
