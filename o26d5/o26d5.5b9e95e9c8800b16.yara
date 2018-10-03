
rule o26d5_5b9e95e9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d5.5b9e95e9c8800b16"
     cluster="o26d5.5b9e95e9c8800b16"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['8d5cd220ad71d042c1c0c67540877e272218466b','7d04f91786d246f3b97c1b3f4f345c1a7829a47d','3f74c216c22982f49e0ae78195bf4a7528dc9c6c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d5.5b9e95e9c8800b16"

   strings:
      $hex_string = { 29ff2a2c2ded697385eb41416e8b2e27719c55607bca4b507bfe483d8efc4d5e8f7f26564f11af978100bda49208ad9c931eb4a79c18c6b6aa16404142612221 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
