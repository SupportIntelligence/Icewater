
rule j3f8_584692921cbb0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.584692921cbb0130"
     cluster="j3f8.584692921cbb0130"
     cluster_size="119"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos origin"
     md5_hashes="['55d58d3e9a0f2c81ad995bae2f5b6eaa83bf5433','5b9e04a2295d8e6f2878cd793f61b0b38976cb67','fa4730f9b92bbed3ed22d6831fefa21350780990']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.584692921cbb0130"

   strings:
      $hex_string = { 2f706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
