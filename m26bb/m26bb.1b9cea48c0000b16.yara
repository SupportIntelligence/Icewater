
rule m26bb_1b9cea48c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.1b9cea48c0000b16"
     cluster="m26bb.1b9cea48c0000b16"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mabezat malicious avce"
     md5_hashes="['aa325a20df966675d9bbfdcdda20777c9e788b9e','c6041966cc7fd770d61ba09e17126a4b6011adec','61c823c92b39db69eec08c0d078ea24f3078f90a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.1b9cea48c0000b16"

   strings:
      $hex_string = { 21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000c758b0df8339de8c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
