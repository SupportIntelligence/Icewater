
rule n2319_6994dcc1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6994dcc1c8000b12"
     cluster="n2319.6994dcc1c8000b12"
     cluster_size="146"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner script"
     md5_hashes="['e1ecfcb4bbb6e9afe1dedc620cef63646dbd0f70','7ce3751052ba4dc733505a110a1f20b7ff86e33c','e72aead15b0538154b4d0c25d121d916270bb0a6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6994dcc1c8000b12"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
