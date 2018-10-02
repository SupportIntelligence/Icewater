
rule n26d4_1192bcc9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.1192bcc9c8000b32"
     cluster="n26d4.1192bcc9c8000b32"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu guildma malicious"
     md5_hashes="['784d90835440673be119d09a0fab7c908e42c22e','2d110be7012e930d4fba0045b7ada58d064c8273','28a8e62d561983171250d7b7e273004bd55ec772']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.1192bcc9c8000b32"

   strings:
      $hex_string = { 08034710014f1089c789cac1e902fcf3a589d183e103f3a45f09db75c65b5f5ec38d4000558bec83c4f8538bd8b201a1e4854100e8ff39feff8945fc33c05568 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
