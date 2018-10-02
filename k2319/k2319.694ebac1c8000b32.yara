
rule k2319_694ebac1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.694ebac1c8000b32"
     cluster="k2319.694ebac1c8000b32"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem script asmalwsc"
     md5_hashes="['29f97cd8915d70ebaa288f4dbb6721ff4266a165','65ae4adbe91da8372fbbcad5c9ee8f622406f4eb','25e96ed5b109acabc5b77becd9042b4aa6170160']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.694ebac1c8000b32"

   strings:
      $hex_string = { 733962273a2236353433222c276f336e273a66756e6374696f6e284f2c75297b72657475726e204f2f753b7d7d3b6368726f6d655b284e304d30382e4238622b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
