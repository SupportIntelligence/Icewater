
rule o26bf_2b9ab849c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bf.2b9ab849c8000b12"
     cluster="o26bf.2b9ab849c8000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="temonde malicious adload"
     md5_hashes="['48ea77b580474226ead43b698322bf0e65e273e1','b2d6a969b8eda390be01c32bea03e99db5fa2de5','b0bd8f2158e793e3a10683c3e9e24af3c22d7d0d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bf.2b9ab849c8000b12"

   strings:
      $hex_string = { fad7b5979fb4bbbe6f347138a105004056367ac99e332c8e7f1b66bf0be75ad9202118c82d67f3e1023424fdf4510f42b25315eb1cb0ae84f8b1f75cdabc7b25 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
