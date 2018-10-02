
rule k2318_270d3399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.270d3399c2200b32"
     cluster="k2318.270d3399c2200b32"
     cluster_size="2179"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['7561d778f289bee737d58781879009fa484304d3','5eada9a7ba0fc114f9ffe9187695e9fa99b3e1fc','795a2a37f9e8cdee3fc515047d6ff4bb2346fdd9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.270d3399c2200b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
