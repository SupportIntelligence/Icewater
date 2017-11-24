
rule i445_0db1f128c0000b22
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0db1f128c0000b22"
     cluster="i445.0db1f128c0000b22"
     cluster_size="6"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jenxcus autorun winlnk"
     md5_hashes="['31099e073854362d994b71ca8a33ed1b','52f38537c1cf84bfcaeb365d2e0a4b21','eed5d45f618d0644228011fc7907cef8']"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c00000000000000000000000000000000000000520031000000000000000000100057696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
