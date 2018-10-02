
rule k2319_103295e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.103295e9c8800b12"
     cluster="k2319.103295e9c8800b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['86bb69cb32412a77057daf4703f3b23889848e36','d010cdbbf4c292d5e3e0328e30ed66b8a8ec6b9b','70bc41054a0c8b1950433b6a1ec1547d1729999f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.103295e9c8800b12"

   strings:
      $hex_string = { 3a2835322e393045312c30783337292929627265616b7d3b7661722066327333793d7b27633379273a66756e6374696f6e28562c4a297b72657475726e20567c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
