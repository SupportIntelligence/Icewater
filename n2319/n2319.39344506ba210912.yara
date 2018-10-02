
rule n2319_39344506ba210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.39344506ba210912"
     cluster="n2319.39344506ba210912"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['92052c198de7837177644e5b044cebe8cd3c379d','af42ea1eb5d5d26f0b38d8c5984968e072f2344b','58bc02ec64656a27f7c8622ddd2ceceb1fbb02a0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.39344506ba210912"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
