
rule k2319_29159eb9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29159eb9c8800b32"
     cluster="k2319.29159eb9c8800b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['436db5d12ec96fcf5967a3b02e33679742abc516','28eea5d8cb037c2108a5de313f25c9a1b325580a','e3aecf108716746a4b1c8a22104919a301634a3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29159eb9c8800b32"

   strings:
      $hex_string = { 313139293a28332e2c32372e292929627265616b7d3b7661722052347639353d7b27413735273a66756e6374696f6e28582c4c297b72657475726e2058213d4c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
