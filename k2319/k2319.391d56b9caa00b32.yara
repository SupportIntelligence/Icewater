
rule k2319_391d56b9caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391d56b9caa00b32"
     cluster="k2319.391d56b9caa00b32"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik asmalwsc crypt"
     md5_hashes="['e28c6cc92eb47c60fd8b3641b39266efd1644a0c','ba34f44063eadc78b535037fd26fa80c87b016e3','2f8305672d0b5b032731ffa1229f29212f97ed3a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391d56b9caa00b32"

   strings:
      $hex_string = { 2830783135452c312e324532292929627265616b7d3b766172204e3647363d7b274e356a273a2263686172222c277a34273a66756e6374696f6e286c2c55297b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
