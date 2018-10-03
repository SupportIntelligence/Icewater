
rule n2319_691457a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.691457a9c8000b12"
     cluster="n2319.691457a9c8000b12"
     cluster_size="152"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinhive"
     md5_hashes="['c86b82eab7ddf8ff0c2f429c9749f21e85fc92f4','778fea15512ecdc57e78a4558b07e32322afde3c','1aacc665d3e3a8f11c360149bc967b98c3cc58f2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.691457a9c8000b12"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
