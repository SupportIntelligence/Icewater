
rule k2319_181914e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181914e9c8800b12"
     cluster="k2319.181914e9c8800b12"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['3631635ed75fe3f04fe9e63fcac548d594f629ef','b8e21c86d745a0997ce6410743059dc5282dd34b','db11fbbb9aaf6ff4f3ccf0be30030392f233ebd7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181914e9c8800b12"

   strings:
      $hex_string = { 32352e2c30783937292929627265616b7d3b766172204e3955383d7b277436273a66756e6374696f6e28542c43297b72657475726e20543e433b7d2c27413379 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
