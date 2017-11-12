
rule o3e9_23c38399c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.23c38399c8000b12"
     cluster="o3e9.23c38399c8000b12"
     cluster_size="722"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadsponsor unwanted bundler"
     md5_hashes="['00bb75b191482fbc96d3b4aaa597adf7','01547761c51f5a9f0c1b27dea90a4c65','078fabdaaaff0ab21c723d933b5fe07f']"

   strings:
      $hex_string = { c0c6eac5004872168a2d83b38c25535ae6b0984fae4c2e925eb12ca14962091aca9c3b6d747751bd905c78a16a99eb30379120a6312f7b13e8450e9af8f7c924 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
