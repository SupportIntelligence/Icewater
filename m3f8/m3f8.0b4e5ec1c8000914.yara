
rule m3f8_0b4e5ec1c8000914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.0b4e5ec1c8000914"
     cluster="m3f8.0b4e5ec1c8000914"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos jisut lockscreen"
     md5_hashes="['611d9277fff0207aeb69f15391977ca9a036239c','8dfbaf95217a319535c8b552b7661a2807c75faf','a34d98758fc6f223248da79e443d0200a9a25219']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.0b4e5ec1c8000914"

   strings:
      $hex_string = { 0e52eea000b1ed82dd70306100cb0d4d0a0809077f07f707f81219220a270007af07fa07fb070c54cca900070d6e1051010d000a0d6e207302dc000a0c82cc12 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
