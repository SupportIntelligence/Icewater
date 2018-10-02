
rule k2319_19311ae9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.19311ae9c8800b32"
     cluster="k2319.19311ae9c8800b32"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem script"
     md5_hashes="['0d0da3314cf802b890eab7a7f51bc0a1bacced03','c65818ba26fff23c6837418e582025ede970634e','c4f990803fec619b1e3d15d3543480c53c35dae4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.19311ae9c8800b32"

   strings:
      $hex_string = { 45322c32342e334531292929627265616b7d3b7661722051307a3d7b276d3167273a3145332c27613844273a222f222c2755273a66756e6374696f6e287a2c64 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
