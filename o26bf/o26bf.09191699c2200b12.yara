
rule o26bf_09191699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bf.09191699c2200b12"
     cluster="o26bf.09191699c2200b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="temonde malicious kryptik"
     md5_hashes="['3d2503d6845d7e3c193655bbdb2783c7efe67ef7','8633b239aa432d0046e9c7f9876f312a727781c7','5ba88cee2e77382ac82e9fb40aa4de13dc82292d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bf.09191699c2200b12"

   strings:
      $hex_string = { 3c737570706f727465644f532049643d227b31663637366337362d383065312d343233392d393562622d3833643066366430646137387d22202f3e2d2d3e0d0a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
