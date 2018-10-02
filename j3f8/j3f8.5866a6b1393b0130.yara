
rule j3f8_5866a6b1393b0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5866a6b1393b0130"
     cluster="j3f8.5866a6b1393b0130"
     cluster_size="448"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos apprisk"
     md5_hashes="['c14179ec6f5c89bf580077548ccb0ff0e4e28793','65e1582b7e2d0244228fca2ba4b323af35665472','251a836d77644b78b9fea3b4b10453bd2584b9f8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5866a6b1393b0130"

   strings:
      $hex_string = { 2f706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
