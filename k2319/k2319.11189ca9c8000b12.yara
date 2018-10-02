
rule k2319_11189ca9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.11189ca9c8000b12"
     cluster="k2319.11189ca9c8000b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['88b945879f34db729beddb099705014319b2e2ec','9d027135360482eec2596c3f5a3e91a96f90131f','d590a77e846ad321777a7dbc9bc497ffc63122ee']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.11189ca9c8000b12"

   strings:
      $hex_string = { 3e307841463f28352e343645322c313139293a2835362c3078313945292929627265616b7d3b7661722076375a39433d7b277a3138273a22696a222c27743738 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
