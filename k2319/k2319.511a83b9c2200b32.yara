
rule k2319_511a83b9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.511a83b9c2200b32"
     cluster="k2319.511a83b9c2200b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b0f1368127d1cc6a613437e894f6a7e875a02f42','2a5152e58133f3021bcfb4a8cf4ce93824f2e9fb','a10d460a0ff4d47f596deccf89dded6ab4a13a0b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.511a83b9c2200b32"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e206c5b515d3b7d76617220453d282830783134432c32352e293c30783233443f2830783146382c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
