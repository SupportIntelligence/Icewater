
rule m2377_3d563949c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.3d563949c8000b32"
     cluster="m2377.3d563949c8000b32"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['272db676206c5ff3dae28bb2f3d3efd9','370b6a2dd2b71f42e1930d834b3b5f48','d46a562bc8929a1a802568de320e8d02']"

   strings:
      $hex_string = { 3d22636f707974657874223e436f707972696768742026233136393b2032303137205361626f72205a756c69616e6f2e20546f646f73206c6f73206465726563 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
