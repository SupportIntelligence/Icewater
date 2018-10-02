
rule nfc8_4932ad94d7a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.4932ad94d7a30912"
     cluster="nfc8.4932ad94d7a30912"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik nymaim"
     md5_hashes="['cc84bd79f7b143a42ebbe0df3833bcb552e7525b','1318c68b13f32b128d4b722be19fa5d881f7eb69','dc57555f8018844d1d93ba1426b88fb06227c984']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.4932ad94d7a30912"

   strings:
      $hex_string = { f8c224fa6d5ac9c8d87e9bc620d734c70743a483117d14b1d4fc250e58b41253ec9f3c1b3779d10129defbe5f3dfb8c00bf65e8e57aff7bc27a65c976933501a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
