
rule k2319_181916e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181916e9c8800b12"
     cluster="k2319.181916e9c8800b12"
     cluster_size="79"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['f05be552787fac48e9bb1bd96d9e3b254dde01c4','b17027e9c23cd58026b542515e283b5dfd6c47af','e457f96c1ffbbc0c6bdaf6d5f04f61f1c3975744']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181916e9c8800b12"

   strings:
      $hex_string = { 32352e2c30783937292929627265616b7d3b766172204e3955383d7b277436273a66756e6374696f6e28542c43297b72657475726e20543e433b7d2c27413379 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
