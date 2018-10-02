
rule n2319_169b04e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.169b04e9c8800b32"
     cluster="n2319.169b04e9c8800b32"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['3d96a3a5f99053c8f86c127c5653aaaacfcbddb0','9320a317f003ff13bbe4d38ca86872b6c269b6c4','d7e2b4fceb54a877d3052db76d68cf772f2e2923']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.169b04e9c8800b32"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
