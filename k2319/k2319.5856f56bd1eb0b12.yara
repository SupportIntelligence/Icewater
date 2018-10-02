
rule k2319_5856f56bd1eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5856f56bd1eb0b12"
     cluster="k2319.5856f56bd1eb0b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['c6ee586cc692f2d062b10fba1444f8f5433a3f1e','cf25986ebddcb092186aa51e7783ad1fa973134b','c37e891ec0745738a9acfe1620d6a7ec3edcb690']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5856f56bd1eb0b12"

   strings:
      $hex_string = { 5b4e5d213d3d756e646566696e6564297b72657475726e20535b4e5d3b7d76617220503d28283130342c30784436293e3d2831342e363845322c30783336293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
