
rule n2319_6994d6c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6994d6c9c8000b12"
     cluster="n2319.6994d6c9c8000b12"
     cluster_size="216"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner script coinhive"
     md5_hashes="['8887d678843116adeeb99dae8961ca5c8af88bd6','b0ed98272fe48fd3b5860925a2531c9f61318c96','672a1beaf9f631622c24768b0e95664232a14f89']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6994d6c9c8000b12"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
