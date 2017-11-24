
rule i445_154b3219c2000922
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.154b3219c2000922"
     cluster="i445.154b3219c2000922"
     cluster_size="26"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dorkbot dobex jenxcus"
     md5_hashes="['0efa5ab6bb05b9a497f4ddd3bd936ad8','1004ea1e1c6f19c3a15785fe49a79628','896ba58013f9fe5bfbe6a7028b5c8057']"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c00000000000000000000000000000000000000520031000000000000000000100077696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
