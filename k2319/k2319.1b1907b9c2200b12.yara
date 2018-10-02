
rule k2319_1b1907b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1b1907b9c2200b12"
     cluster="k2319.1b1907b9c2200b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['35c59f94c502dd6a7a8593c91e3fa44a4eebd2b2','7d7da109c9a3879c61b3eac6cf3c0f6f98bd4c32','c340af5651596b339a3103e4f2bad4fcb63a5e8b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1b1907b9c2200b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e204b5b475d3b7d766172204c3d2836382e313045313e28312e31383345332c313333293f2830783133412c3078636339653264 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
