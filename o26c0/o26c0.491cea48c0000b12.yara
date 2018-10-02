
rule o26c0_491cea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.491cea48c0000b12"
     cluster="o26c0.491cea48c0000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious heuristic amlioos"
     md5_hashes="['448b783397c62171425cd58088d73bdfab860040','552f232eeec6995b1cfc56b6419af126ef23ac5b','c21ef8e669238e23f5aef9d9de11a8e1d5161253']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.491cea48c0000b12"

   strings:
      $hex_string = { 8d46185750e88ec8ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
