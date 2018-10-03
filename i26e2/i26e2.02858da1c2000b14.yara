
rule i26e2_02858da1c2000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26e2.02858da1c2000b14"
     cluster="i26e2.02858da1c2000b14"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dorkbot winlnk autorun"
     md5_hashes="['ecb8c8dcd1b8a3c7c1c5405601528723f1878df4','15186c2404f5a237b863649a922e9afe7ce7035d','6cf748b015aaebab3cfb57463800424da2db80ab']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26e2.02858da1c2000b14"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c000000000000000000000000000000000000003c0031000000000000000000100077696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
