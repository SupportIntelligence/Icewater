
rule o26c0_49166a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.49166a48c0000b12"
     cluster="o26c0.49166a48c0000b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious heuristic amlioos"
     md5_hashes="['0e4c6b8f5194b6e73b7b9847d8fc01705af6068c','c3fb3a3ed76a5c43d32bb16d833d163a52499252','884318170f3b65523da45f515df73b6a643f3895']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.49166a48c0000b12"

   strings:
      $hex_string = { 8d46185750e88ec8ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
