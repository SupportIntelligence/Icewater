
rule n2319_11b931a9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.11b931a9c8800932"
     cluster="n2319.11b931a9c8800932"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner script coinhive"
     md5_hashes="['6ca9322f13dc797792b696d07c2ae15e1144b176','4454b5be291be4b158af15a10929a86b55ec89ee','87259814b49a8549e96e3d63ae9d4a5276c58af0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.11b931a9c8800932"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
