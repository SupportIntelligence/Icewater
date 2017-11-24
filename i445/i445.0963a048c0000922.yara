
rule i445_0963a048c0000922
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0963a048c0000922"
     cluster="i445.0963a048c0000922"
     cluster_size="4"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbsworm winlnk jenxcus"
     md5_hashes="['21abe1f12755dd4e3f1f9cdd5a0de3b6','5c56d10da11ebc0c017311f7c76f1a3d','fe43bd30b7999704d879dfab2b0925c4']"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c00000000000000000000000000000000000000520031000000000000000000100057696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
