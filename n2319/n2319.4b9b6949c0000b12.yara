
rule n2319_4b9b6949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.4b9b6949c0000b12"
     cluster="n2319.4b9b6949c0000b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack clickjack script"
     md5_hashes="['c6273e26c52c5aa8943c1ac4710b39679261604f','da7fff17511d1b7d6419d1b60f17149d80fbf928','a054f720676b1d3ea31bff2a4305e64f4d7339f2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.4b9b6949c0000b12"

   strings:
      $hex_string = { 2b2230313233343536373839414243444546222e63686172417428625b635d253136293b72657475726e20617d3b0a78633d2121776326262266756e6374696f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
