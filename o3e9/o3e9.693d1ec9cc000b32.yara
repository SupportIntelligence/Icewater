
rule o3e9_693d1ec9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.693d1ec9cc000b32"
     cluster="o3e9.693d1ec9cc000b32"
     cluster_size="78"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock zrtrei nabucur"
     md5_hashes="['0699dbf0083c169d66438549a73a79af','0b940f6b56daaf40a72ad6bf42ae2828','88cadb52852f93531e5c3d37b859f013']"

   strings:
      $hex_string = { f8d5b4fff5d3b3fff3d0b2fff0ceb0ffeecbafffeccaadffebc8acffe8c6aaffe5c3a9ffe3c1a7ffe2c0a6ffe0bea4ffddbba3ffdab9a2ffdeae8fc6dfac8514 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
