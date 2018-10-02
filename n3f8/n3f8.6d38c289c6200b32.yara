
rule n3f8_6d38c289c6200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6d38c289c6200b32"
     cluster="n3f8.6d38c289c6200b32"
     cluster_size="504"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos backdoor banker"
     md5_hashes="['3df3b883f5fa4f632a533c7c5583fb56dfac0f18','84b76965d67efd23d44d452cf4e0fdffb802897e','03f48e8f5a8e4f93da4fb06303a008d1853fa347']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6d38c289c6200b32"

   strings:
      $hex_string = { 012a044a0900007f016b02a10a000080011d038b0b000081011d038b0b000081016b0270110000820135016f0e000082013601700e000083015f04d009000084 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
