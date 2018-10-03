
rule m231b_69956a49c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.69956a49c0000912"
     cluster="m231b.69956a49c0000912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script faceliker html"
     md5_hashes="['45044e99d0767b2582e35ebcdea1b081a7714ad6','cbd417959f83bc1e4969a5c96071e347fa6c9526','be96632a89c7601120bd5035f8158d34d041ef48']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.69956a49c0000912"

   strings:
      $hex_string = { 20302c20302c20302e3135293b0a7d0a236372656469742d777261707065727b6261636b67726f756e643a236639663966393b77696474683a39363270783b6d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
