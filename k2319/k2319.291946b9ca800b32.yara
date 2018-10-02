
rule k2319_291946b9ca800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291946b9ca800b32"
     cluster="k2319.291946b9ca800b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['7f616747c99bc9d085f3c02c0ef7455d3c7d24ec','d9c6d3b6b93eb3bdd39127891d82abe366a078bc','22ccd0736b857548c93b2a2f5f5ce18cf36a5007']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291946b9ca800b32"

   strings:
      $hex_string = { 66696e6564297b72657475726e20565b6c5d3b7d76617220493d282830783138392c31372e304531293e3d283134312e3945312c33372e293f2830783136422c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
