
rule k2319_1a109eb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a109eb9c8800b12"
     cluster="k2319.1a109eb9c8800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['f3dc652c7597b87ec04d6e47f1106dd77aafaa63','e8363ab82415b681d7822e224e541936206c07d1','1b638f8de395db9e308ed3a45001209b5e0cf9e2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a109eb9c8800b12"

   strings:
      $hex_string = { 312e3032364533292929627265616b7d3b7661722075304a35353d7b2744384d273a2268222c2746346c273a2264222c274a3835273a66756e6374696f6e2877 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
