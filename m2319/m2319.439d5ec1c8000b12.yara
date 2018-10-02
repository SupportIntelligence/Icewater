
rule m2319_439d5ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.439d5ec1c8000b12"
     cluster="m2319.439d5ec1c8000b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframeinject script crypt"
     md5_hashes="['9ed339258af80af8bf1b6ac6e4fd69f884f2647d','46faeb0a2c1e00f4de411b43bddf902d8e8d5f3c','4ac4c92824c461dfeb3e177c0ac6f5f331146e73']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.439d5ec1c8000b12"

   strings:
      $hex_string = { 7b0a6261636b67726f756e643a233946314432363b0a77696474683a2031353070783b0a636f6c6f723a20236666663b0a666f6e742d73697a653a2031337078 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
