
rule j3f8_5846b29018bb0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5846b29018bb0130"
     cluster="j3f8.5846b29018bb0130"
     cluster_size="358"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos origin"
     md5_hashes="['32a473ea45fcfddfd7e3da9e13af9adcd4343f6e','0edb3cdd423c3e58f5e73bceac634c20899f630d','7ad87b49bb70105ea160c707f7e1c6988b2ca271']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5846b29018bb0130"

   strings:
      $hex_string = { 706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e64726f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
