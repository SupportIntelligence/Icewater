
rule j26bf_21b32000c0001112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.21b32000c0001112"
     cluster="j26bf.21b32000c0001112"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo malicious applicunwnt"
     md5_hashes="['1f3561747329ef8c41e6e6330b79087881027fc7','bfff21ef566ff2d51cf6dd8d4adaf63729bf7b85','aae1452a8632375f49e97ef77885a4c15829c626']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.21b32000c0001112"

   strings:
      $hex_string = { 00446562756767696e674d6f6465730053797374656d2e52756e74696d652e436f6d70696c6572536572766963657300436f6d70696c6174696f6e52656c6178 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
