
rule k26d7_513235a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26d7.513235a9c8000b32"
     cluster="k26d7.513235a9c8000b32"
     cluster_size="140"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="java genericgb keylogger"
     md5_hashes="['d6ff8ef9c42ad7151d9df1b682511525fd418f9e','a1faee7eeb3d82acbd5d21911d1e31c1d356c8c0','279bdbb300d595f2369b4f5096bbef396377a4b6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26d7.513235a9c8000b32"

   strings:
      $hex_string = { ec188b75f085c00f94c10fb6f9897de8893424e87836000083ec04c643ff5c8b45e88d65f45b5e5f5dc3897c240431c98d55f089542410b8190102008944240c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
