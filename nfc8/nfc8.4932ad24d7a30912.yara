
rule nfc8_4932ad24d7a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.4932ad24d7a30912"
     cluster="nfc8.4932ad24d7a30912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="nymaim razy bfhh"
     md5_hashes="['602d4d7303d7b196e079f34e2b48864b689787a9','9475c86d7eb0dafa9f9d0ad30d0301704d557204','cd1d8f66b0884cb5c958e0c5f19aff3c7d6e697c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.4932ad24d7a30912"

   strings:
      $hex_string = { f8c224fa6d5ac9c8d87e9bc620d734c70743a483117d14b1d4fc250e58b41253ec9f3c1b3779d10129defbe5f3dfb8c00bf65e8e57aff7bc27a65c976933501a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
