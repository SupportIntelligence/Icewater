
rule h26d4_6a544086c2210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=h26d4.6a544086c2210b32"
     cluster="h26d4.6a544086c2210b32"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="unsafe fraudtool heuristic"
     md5_hashes="['6cba7883b2b8f400528db71e80c00b330bfdbbb1','e4d13201d49b7f1f7459ddf461d2d245966efa27','6ee471a28debd11a828877cbde9ead89031b49c3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=h26d4.6a544086c2210b32"

   strings:
      $hex_string = { 21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a240000000000000066bad1a222dbbff1 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
