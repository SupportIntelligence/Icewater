
rule o26bb_29128508d9e30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.29128508d9e30912"
     cluster="o26bb.29128508d9e30912"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious susp"
     md5_hashes="['ef44d5b6a33edddeadaf0323d84119a3279b8d9b','e69ec31753736e3addd1db3ed43590d4cfb144d2','65d73ce535bf71590a4c998807e1046e0c1f3825']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.29128508d9e30912"

   strings:
      $hex_string = { 0309533fce0da1a37241067eee820ee638a9d21eabdd3eda3c24e1ad29b1c1ebb8e3d169ef629d60a635046cc38643f41c8f362da018de6a85fbe8f69f676819 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
