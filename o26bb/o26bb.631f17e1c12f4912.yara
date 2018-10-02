
rule o26bb_631f17e1c12f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.631f17e1c12f4912"
     cluster="o26bb.631f17e1c12f4912"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['67b703cda4d784a7a5c0a18a0b97f3ab27b2522b','75b283020d1501884702f228ac1f938b0b8f0dd2','7c8301f452aeda6a38e70e7628776eb272bc3e02']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.631f17e1c12f4912"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
