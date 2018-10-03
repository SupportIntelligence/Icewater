
rule o26bf_099d6a45c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bf.099d6a45c0000b12"
     cluster="o26bf.099d6a45c0000b12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="temonde malicious kryptik"
     md5_hashes="['48938dcf159f4b21d993fe8c40e5ea637c2506e2','c3024987a26d92b484ccd031fcc0353eebd608c8','f0e5031fadc94265c16cbaa607221c6a160a0b92']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bf.099d6a45c0000b12"

   strings:
      $hex_string = { 3c737570706f727465644f532049643d227b31663637366337362d383065312d343233392d393562622d3833643066366430646137387d22202f3e2d2d3e0d0a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
