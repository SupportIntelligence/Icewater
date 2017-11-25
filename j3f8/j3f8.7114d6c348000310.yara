
rule j3f8_7114d6c348000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7114d6c348000310"
     cluster="j3f8.7114d6c348000310"
     cluster_size="16"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['0b9a5c9530081be1512c97674454a546','1951aafbfd67bbe62547c9af2a55de5a','f0ae2e386a32cde450a0160225a654d5']"

   strings:
      $hex_string = { 086d436f6e7465787400136d496e697469616c4170706c69636174696f6e000e6d4c6f63616c50726f766964657200096d5061636b61676573000c6d50726f76 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
