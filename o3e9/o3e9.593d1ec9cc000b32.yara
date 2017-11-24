
rule o3e9_593d1ec9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.593d1ec9cc000b32"
     cluster="o3e9.593d1ec9cc000b32"
     cluster_size="44"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur polyransom"
     md5_hashes="['2d4f6f844398ca38c6453d03a5cf7509','3acbdf822c4167c43783b695dea16282','b2b66d6bb81f59ffa4f33a2916c6b510']"

   strings:
      $hex_string = { f8d5b4fff5d3b3fff3d0b2fff0ceb0ffeecbafffeccaadffebc8acffe8c6aaffe5c3a9ffe3c1a7ffe2c0a6ffe0bea4ffddbba3ffdab9a2ffdeae8fc6dfac8514 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
