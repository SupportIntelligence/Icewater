
rule j26bf_0a56e747ae210b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.0a56e747ae210b10"
     cluster="j26bf.0a56e747ae210b10"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo malicious heuristic"
     md5_hashes="['c270c23f21923d897c0ab49a77dc946211fc2b4a','45dde276aa4ca86b554d41c97d487c50f46f5d9b','b9f3b4bebab750046e252560a1366c7b61a5c519']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.0a56e747ae210b10"

   strings:
      $hex_string = { 6c79436f6e66696775726174696f6e41747472696275746500417373656d626c79436f6d70616e7941747472696275746500417373656d626c7950726f647563 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
