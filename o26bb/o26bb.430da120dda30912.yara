
rule o26bb_430da120dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.430da120dda30912"
     cluster="o26bb.430da120dda30912"
     cluster_size="153"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler adload malicious"
     md5_hashes="['36fdbcc5d3999093a838feb5b7d74e01ff677664','be69ac7db82abf0fbd41701f8e2a58b2d453024d','540dd7c5e41588ad4019d155568ed67d706a5061']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.430da120dda30912"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
