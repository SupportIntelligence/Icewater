
rule k2319_29194699c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29194699c2200b32"
     cluster="k2319.29194699c2200b32"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['52ef34f51288f523ac12902965a468e7941a7482','c630ad05b34cec1f23fc5e0dc9ef975915ed23d9','530e072852907f86fca80cdef42e7c690cb48c1d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29194699c2200b32"

   strings:
      $hex_string = { 66696e6564297b72657475726e20565b6c5d3b7d76617220493d282830783138392c31372e304531293e3d283134312e3945312c33372e293f2830783136422c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
