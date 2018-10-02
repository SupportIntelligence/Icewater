
rule m26bb_1b94ea49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.1b94ea49c0000b12"
     cluster="m26bb.1b94ea49c0000b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mabezat malicious avce"
     md5_hashes="['8639324e02a100b3e110c93a978d53f1fa5b4ad5','17a64ffca221efc72d34cb7ca000e8e190db6a5b','ece4020c906a608cde7fe2f390ad04421d8f29c4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.1b94ea49c0000b12"

   strings:
      $hex_string = { 21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000c758b0df8339de8c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
