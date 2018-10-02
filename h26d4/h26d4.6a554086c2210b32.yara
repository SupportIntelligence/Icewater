
rule h26d4_6a554086c2210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=h26d4.6a554086c2210b32"
     cluster="h26d4.6a554086c2210b32"
     cluster_size="116"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fraudtool heuristic malicious"
     md5_hashes="['f6010c92b85947198a5fbc2baea97c7344392f50','976d69a8b43986e0c9a6e271071374787e5d2c66','d1e4db47e48ab4835ecaa27de12a83e9b3d89354']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=h26d4.6a554086c2210b32"

   strings:
      $hex_string = { b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a240000000000000066bad1a222dbbff122 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
