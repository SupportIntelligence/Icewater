
rule o26bb_430ca0b4dda30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.430ca0b4dda30b12"
     cluster="o26bb.430ca0b4dda30b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['fd0d49d27ac41074e9e9aef79fb791a7aa9dee48','b5bb468c4a7ccc3815cebdafe839058370ed5b7c','d352571156441cadd33e02eb965acf176bb259d7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.430ca0b4dda30b12"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
