
rule n2319_51bb13a9ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.51bb13a9ca000912"
     cluster="n2319.51bb13a9ca000912"
     cluster_size="75"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner bitcoinminer coinminer"
     md5_hashes="['465b99c6a4b97f04a78c74d04635177b1bb9d2d6','088170b62dfadb69cc519d74fefa9a65364e67f5','c073da50d28f32c9d5c29ac444e62103fa3d5270']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.51bb13a9ca000912"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
