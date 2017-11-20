
rule m3e9_31b9e848c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31b9e848c0000b32"
     cluster="m3e9.31b9e848c0000b32"
     cluster_size="55"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="swrort elzob zusy"
     md5_hashes="['0ce52f5799530cadbc6c5603a04a863a','0e4525640c895e9f67c41a37a60605f1','4d0c0c4149376d1f5146fd03423ddd58']"

   strings:
      $hex_string = { 404142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
