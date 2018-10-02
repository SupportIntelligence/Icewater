
rule k2319_5a119699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a119699c2200b12"
     cluster="k2319.5a119699c2200b12"
     cluster_size="136"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['bc4a6b2482d68dcab260a94cf9042c1e45e116cb','2261d390898b6cd062e5a83ab37f9f156ac35172','0ac337fa2d35f2b7eaddb1359482d30857d20d22']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a119699c2200b12"

   strings:
      $hex_string = { 365b745d213d3d756e646566696e6564297b72657475726e204c365b745d3b7d766172206c3d283133332e3c2834352e2c3078323332293f28312c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
