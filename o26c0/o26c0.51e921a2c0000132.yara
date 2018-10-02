
rule o26c0_51e921a2c0000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.51e921a2c0000132"
     cluster="o26c0.51e921a2c0000132"
     cluster_size="848"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious kryptik attribute"
     md5_hashes="['56c32e59514b93c9f69e78f3916056ef3dcce19c','4c85841f21a79b01c847c16c71a69c6009807166','9f21b0766eee44a5aadd348e730236c80fe1c8f1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.51e921a2c0000132"

   strings:
      $hex_string = { 8d46185750e809cfffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
