
rule i445_02858da1c2000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.02858da1c2000b14"
     cluster="i445.02858da1c2000b14"
     cluster_size="5"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dorkbot autorun dobex"
     md5_hashes="['174d8b18b9573ea8c7f6af125f5b6fbe','1bcfcbc7c649d418935c4147b0e6dc9c','c13936b70ea1216b7e3fa514616cda42']"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c000000000000000000000000000000000000003c0031000000000000000000100077696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
