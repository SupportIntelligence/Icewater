
rule n2319_6994d1e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6994d1e9ca000b12"
     cluster="n2319.6994d1e9ca000b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner script coinhive"
     md5_hashes="['ee4503c3b1058cb05e30c50499c785e3cf7b8f6d','691a37d4de9722865b963a3bb7e0b299d136807f','7a3a6206cded95c7e53a895f571298958588cb01']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6994d1e9ca000b12"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
