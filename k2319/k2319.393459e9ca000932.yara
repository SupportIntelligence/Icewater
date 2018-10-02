
rule k2319_393459e9ca000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.393459e9ca000932"
     cluster="k2319.393459e9ca000932"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['2c7951a5c655db1c9478fa4e532e2df28bc06aa8','dd45f60d21d658174d1c738835305e0a323335af','beb4395dafaf00064f5e83e08def6a193f1f31a8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.393459e9ca000932"

   strings:
      $hex_string = { 465b495d213d3d756e646566696e6564297b72657475726e20465b495d3b7d766172206b3d2828307836302c3078323534293e35382e3f28312e30383745332c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
