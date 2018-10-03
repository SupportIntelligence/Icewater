
rule n2319_6994dec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6994dec1c8000b12"
     cluster="n2319.6994dec1c8000b12"
     cluster_size="179"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinhive"
     md5_hashes="['11ce6cf09024d05d7d1a46256cbb0d1a3fbe219a','c26db9f8a834f6b893a26e4f1d7a0a80b4ed5ca3','9a87b5b846799a32f8043d66584038de138df46f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6994dec1c8000b12"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
