
rule m2319_431ddec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.431ddec1c8000b12"
     cluster="m2319.431ddec1c8000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script crypt fundf"
     md5_hashes="['477e370b905168813c3f9c6573044cf52860c583','d88dbf18c8c96ab246b8726f3cf1e79b72a403b8','aa5fb3fa6b1c95412ae992cf8706aad6f1ad8525']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.431ddec1c8000b12"

   strings:
      $hex_string = { 7b0a6261636b67726f756e643a233946314432363b0a77696474683a2031353070783b0a636f6c6f723a20236666663b0a666f6e742d73697a653a2031337078 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
