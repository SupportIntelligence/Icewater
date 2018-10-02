
rule m2319_39526a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.39526a48c0000b32"
     cluster="m2319.39526a48c0000b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['b01928aef0930c43813771411560c8c27eaa6299','ba1facf7bc36ad9cf4a9fed6843c17c461878ce8','ef82fd3ffb2a095e5e33851314c8066dd64cec35']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.39526a48c0000b32"

   strings:
      $hex_string = { 43454d454e555f44524f505f414c4c4f575f5749445448333634203d2066616c73653b0a0d66756e6374696f6e20737461727447616c6c6572792829207b0a09 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
