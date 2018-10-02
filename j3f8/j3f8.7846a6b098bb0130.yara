
rule j3f8_7846a6b098bb0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7846a6b098bb0130"
     cluster="j3f8.7846a6b098bb0130"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos origin"
     md5_hashes="['9c725ea3ce9c16c488d1ee7980d5c5d2d7648821','cb1fdf2006fd4d52d8912091b3084722f4800298','076d5f2fdb699f6f1a04fc1a499da1b80c677e4a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.7846a6b098bb0130"

   strings:
      $hex_string = { 2f706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
