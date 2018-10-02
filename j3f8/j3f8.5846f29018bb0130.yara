
rule j3f8_5846f29018bb0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5846f29018bb0130"
     cluster="j3f8.5846f29018bb0130"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos apprisk"
     md5_hashes="['0229ef92027b7ddb93732c6f1bb60956e67902d6','28dd6d14bf855fcdfb54fa6347b380593cffb50b','59774f5cfc2277f444b6ac124283b8a4c97bf6da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5846f29018bb0130"

   strings:
      $hex_string = { 2f706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
