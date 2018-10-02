
rule m26bb_4694ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.4694ea48c0000b32"
     cluster="m26bb.4694ea48c0000b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mabezat malicious avce"
     md5_hashes="['04ad0f1ccf4b5a24234e184b7082863f3bfed685','cd3107e7969b0322914e95e15abbd65fd8913684','e6e99498661af9a72ae768de8083cb715f6dc8cd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.4694ea48c0000b32"

   strings:
      $hex_string = { b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000c758b0df8339de8c83 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
