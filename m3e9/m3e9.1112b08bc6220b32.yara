
rule m3e9_1112b08bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1112b08bc6220b32"
     cluster="m3e9.1112b08bc6220b32"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz banker"
     md5_hashes="['19238d97a57f75900df984b5d57d3c9a','2b2777e8591e7453c8253f63d9568fe9','ecf01f6eae5621423850e40157ba1d53']"

   strings:
      $hex_string = { cd781e267df220b385e3392ac5f1af8c96605913ccb9b416bdb83e1bbcf51d374b4a9e01d7ca3139067b4d2dc7d1de5c29d3dc3c65ac8f0e321fc2d9767a46a6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
