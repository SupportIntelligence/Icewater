
rule n2319_13b36316ea210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13b36316ea210932"
     cluster="n2319.13b36316ea210932"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['7d8ec14b03da4d80fffc7016883d5aa25b6f75d7','55c34d57e1776fd9a2cbdfd9cc7450abe43e78cb','9b20ec0e012bae079a44d3675360a0d631adb3ad']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13b36316ea210932"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
