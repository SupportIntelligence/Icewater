
rule j3e7_7094d6c3c8000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7094d6c3c8000130"
     cluster="j3e7.7094d6c3c8000130"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos revo"
     md5_hashes="['06b33c682324f9a29a3a199cf7076dff','06f98f50c09998bca5ff4422ef6935bc','af6a2538f8d9ec9e265c8563eac7d579']"

   strings:
      $hex_string = { 086d436f6e7465787400136d496e697469616c4170706c69636174696f6e000e6d4c6f63616c50726f766964657200096d5061636b61676573000c6d50726f76 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
