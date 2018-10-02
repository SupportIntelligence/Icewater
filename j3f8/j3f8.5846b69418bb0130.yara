
rule j3f8_5846b69418bb0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5846b69418bb0130"
     cluster="j3f8.5846b69418bb0130"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos apprisk"
     md5_hashes="['6fab74229b4cea6f2f63b1b03bd264b240d646ad','3830cee712ec78a2a641a316fec80f4ca80a68ed','fde3dd14f1c6b09ec0cfc28997fbf4ce8e14529d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5846b69418bb0130"

   strings:
      $hex_string = { 2f706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
