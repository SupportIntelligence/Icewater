
rule h26d4_2a554086c2210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=h26d4.2a554086c2210b32"
     cluster="h26d4.2a554086c2210b32"
     cluster_size="60"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="unsafe fraudtool heuristic"
     md5_hashes="['3d2fa75e6e487727731270e8063c6ae3ba1fd620','756f60531e31f5816cca780e1f428c1a9af4b4c8','a668f0a44310903e522535da11f6c9cefa0e6b64']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=h26d4.2a554086c2210b32"

   strings:
      $hex_string = { 21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a240000000000000066bad1a222dbbff1 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
