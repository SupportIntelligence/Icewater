
rule j3f8_7866b6b01a9b0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7866b6b01a9b0130"
     cluster="j3f8.7866b6b01a9b0130"
     cluster_size="85"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos origin"
     md5_hashes="['84ac39ecd273befd22b93742c6564b2334f0de01','9a876b1a0f41256a727f2c9d29b2680c7fcc91bd','5ec69faca2c7893da1dbda7741835059f14aec9c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.7866b6b01a9b0130"

   strings:
      $hex_string = { 2f706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
