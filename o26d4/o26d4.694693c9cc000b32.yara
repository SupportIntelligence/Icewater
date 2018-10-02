
rule o26d4_694693c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.694693c9cc000b32"
     cluster="o26d4.694693c9cc000b32"
     cluster_size="59"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy gamehack malicious"
     md5_hashes="['a7b429b039fb4e6f37ef1f64bb153cddbfcfc7a6','9cbe83a5337982ab9ce3845e7885a83832272d1f','8fdcd7c834d79319148bb573aba42c249a560fcd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.694693c9cc000b32"

   strings:
      $hex_string = { bd005897bd00a09d3c00a09d3c0044013e0044013e00d89f3d00d89f3d00c0c5bc00c0c5bc0040a2bd0040a2bd00201ebe00201ebe00603fbe00603fbe00f0e7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
