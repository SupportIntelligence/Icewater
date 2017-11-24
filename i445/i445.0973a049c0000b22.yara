
rule i445_0973a049c0000b22
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0973a049c0000b22"
     cluster="i445.0973a049c0000b22"
     cluster_size="6"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbsworm winlnk jenxcus"
     md5_hashes="['01541a27850f84e8c9805d6fd3a5185c','1b4052001e8c3c45694deb721a0edb84','be38084eaeca9cd74c0dabdfba1b7caf']"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c00000000000000000000000000000000000000520031000000000000000000100057696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
