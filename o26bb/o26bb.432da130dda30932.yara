
rule o26bb_432da130dda30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.432da130dda30932"
     cluster="o26bb.432da130dda30932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['4905c9e4359394ffc7d63dfceda5aa14ebc0ea6b','7461b2a4c9f6c53ebabb1b0754b7e397f16c68aa','37f3bc621a4e0c4fb0c4cc2e8ce748ce68289387']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.432da130dda30932"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
