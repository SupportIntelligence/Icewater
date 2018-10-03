
rule m2319_2b9352aadb4bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b9352aadb4bd912"
     cluster="m2319.2b9352aadb4bd912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink script html"
     md5_hashes="['f4e28755054f0e79a8ac70ef97475e9b517f6c16','3199f089d356752344d5c034250fc4d7fcc8c897','10ec134916be7c583db92d5628108e15cec0ea15']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2b9352aadb4bd912"

   strings:
      $hex_string = { 696f6e2861297b72657475726e20613f612e7265706c616365282f5b21222425262728292a2b2c2e5c2f3a3b3c3d3e3f405c5b5c5d5c5e607b7c7d7e5d2f672c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
