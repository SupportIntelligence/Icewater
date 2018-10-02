
rule o26d5_499b1de9c8800916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d5.499b1de9c8800916"
     cluster="o26d5.499b1de9c8800916"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['bd14336762431230e66018e0d457b5e5b9d17ca1','fcba55b9cda0060b5fb1f9d882290a78baa565bb','3e41c73fc074754503d5c4b8ca9de493579e1f82']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d5.499b1de9c8800916"

   strings:
      $hex_string = { 29ff2a2c2ded697385eb41416e8b2e27719c55607bca4b507bfe483d8efc4d5e8f7f26564f11af978100bda49208ad9c931eb4a79c18c6b6aa16404142612221 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
