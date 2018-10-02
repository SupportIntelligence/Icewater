
rule k2319_111196b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.111196b9c8800b12"
     cluster="k2319.111196b9c8800b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik expkit script"
     md5_hashes="['1704e20db9a821bdcf1d463a785f387a1e6604cc','94f6baf6859a6dc670923400f3cac1675be579dc','2d15d495ab5757dee95453274fbdd2031a654a64']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.111196b9c8800b12"

   strings:
      $hex_string = { 2837312e3945312c30784139292929627265616b7d3b76617220583175374d3d7b2770326d273a312c274e354d273a66756e6374696f6e28452c4f297b726574 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
