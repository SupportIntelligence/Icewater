
rule n2319_53192949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.53192949c0000b12"
     cluster="n2319.53192949c0000b12"
     cluster_size="76"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker script"
     md5_hashes="['e1b60b4f2cdbe49fb92fabdf106cbce3dec0de68','1639775e082e4cfb7639afe26cb3702995ea55a6','b9a9a8dee39984ff0f82e7c9c1644b3919f73dff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.53192949c0000b12"

   strings:
      $hex_string = { 297d3b766172206b623d6465636f64655552492822253733637269707422292c6c623d2f5e5b2d2b5f302d395c2f412d5a612d7a5d2b3d7b302c327d242f2c6d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
