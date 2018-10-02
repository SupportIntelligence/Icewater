
rule j3f8_7866b6b018bb0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7866b6b018bb0130"
     cluster="j3f8.7866b6b018bb0130"
     cluster_size="319"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos apprisk"
     md5_hashes="['f3a5039aed877ab557e54d4a443191954125e225','57b6cff822691a2694a8e3a033a2443f12be9248','1ec964bb479edf8e21af630b7699fedfc9b51bb2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.7866b6b018bb0130"

   strings:
      $hex_string = { 2f706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
