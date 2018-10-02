
rule j3f8_58469292589b0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.58469292589b0130"
     cluster="j3f8.58469292589b0130"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos faae"
     md5_hashes="['6454d0d1fe8f6ac559b4d3a8118cdf7c72a25812','8a0d581c956290d81690dec6885b6c06f5ad768c','8acf3f4f92de93ca9603f3e3398d9b7c92b509bc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.58469292589b0130"

   strings:
      $hex_string = { 2f706d2f4170706c69636174696f6e496e666f3b00234c616e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b00224c616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
