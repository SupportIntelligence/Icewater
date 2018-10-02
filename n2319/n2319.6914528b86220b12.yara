
rule n2319_6914528b86220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6914528b86220b12"
     cluster="n2319.6914528b86220b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['d51e6435e066c7d7835f82c084d7e7abbf6761b8','03606512c3f9a3f1c69a4cb07eed7c7d43bfb688','ba3e0536e9c2a673d5ad9bb96f2abeae366edaaa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6914528b86220b12"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
