
rule m26bb_1a94ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.1a94ea48c0000b12"
     cluster="m26bb.1a94ea48c0000b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mabezat malicious crypt"
     md5_hashes="['7067a7d5816e84a18f52c44e4689476248c9465d','966b1d3031aaf8da349e2e59bb98567f88de893d','7f594f5139f0fdee8fdeb3678d554dd6e99bd8a5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.1a94ea48c0000b12"

   strings:
      $hex_string = { 21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000c758b0df8339de8c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
