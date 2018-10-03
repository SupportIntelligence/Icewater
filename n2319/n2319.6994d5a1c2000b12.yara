
rule n2319_6994d5a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6994d5a1c2000b12"
     cluster="n2319.6994d5a1c2000b12"
     cluster_size="97"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer coinhive"
     md5_hashes="['698b23a10916964ab8661da68a8e41bacb227ae8','4da1aac338c44651efefa01f4a842efae06d1ca9','39c8e78844dda70c7de3605d5e7e4d09fef97fe7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6994d5a1c2000b12"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
