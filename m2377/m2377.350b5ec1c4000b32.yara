
rule m2377_350b5ec1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.350b5ec1c4000b32"
     cluster="m2377.350b5ec1c4000b32"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['0e993c99e673c2eaf8cdde766fc9f21a','26f740ccc13ba267a1a75df429368c2d','c1cdddcf0e13dd1d02fa6be1dbca2dbe']"

   strings:
      $hex_string = { 3d22636f707974657874223e436f707972696768742026233136393b2032303137205361626f72205a756c69616e6f2e20546f646f73206c6f73206465726563 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
