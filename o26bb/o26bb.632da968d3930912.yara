
rule o26bb_632da968d3930912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.632da968d3930912"
     cluster="o26bb.632da968d3930912"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious malwarex"
     md5_hashes="['508c85ef0d57dde96368e087fb93d5bd75d21cd1','6df232ea088dc52a53e93f398b7b91d5480a720d','d90a6c19c6790f17aa88ef92cd0c52ab01ed8ff8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.632da968d3930912"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
