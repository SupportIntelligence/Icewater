
rule o3e9_623c9ec9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.623c9ec9cc000b32"
     cluster="o3e9.623c9ec9cc000b32"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock cryptor malicious"
     md5_hashes="['ab8d2d2b0413b3c3b5ee9526512ef625','b8342868a50c1b6e28f888f94824df0c','d99058c415b42b6c19f1bb7703a5ab0f']"

   strings:
      $hex_string = { f8d5b4fff5d3b3fff3d0b2fff0ceb0ffeecbafffeccaadffebc8acffe8c6aaffe5c3a9ffe3c1a7ffe2c0a6ffe0bea4ffddbba3ffdab9a2ffdeae8fc6dfac8514 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
