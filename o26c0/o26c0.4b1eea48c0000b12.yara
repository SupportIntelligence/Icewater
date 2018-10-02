
rule o26c0_4b1eea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.4b1eea48c0000b12"
     cluster="o26c0.4b1eea48c0000b12"
     cluster_size="142"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious genericrxer kryptik"
     md5_hashes="['ee6c4cd9d6f4d264e5a425d604869d0b7ff4837c','72608036121c8a9cd9d8a288eee5f62c195323f9','7da9d89e9d3d5351eb3b9948c481358a6b40c9f3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.4b1eea48c0000b12"

   strings:
      $hex_string = { f940731580f92073060fa5c2d3e0c38bd033c080e11fd3e2c333c033d2c3cc833d544b4100007437558bec83ec0883e4f8dd1c24f20f2c0424c9c3833d544b41 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
