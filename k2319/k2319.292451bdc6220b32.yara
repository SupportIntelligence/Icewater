
rule k2319_292451bdc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.292451bdc6220b32"
     cluster="k2319.292451bdc6220b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['dd8d93c9fa23bb8903ddd47942f64ddfede71de7','566488e063480ccba9b4b5b7dd6e41db79d63949','8b08ca2a4f0a577ba13c8df1337730eb9b0e03a3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.292451bdc6220b32"

   strings:
      $hex_string = { 28307836392c30784330292929627265616b7d3b766172207a3341324d3d7b27633237273a2241222c27573559273a66756e6374696f6e286a2c70297b726574 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
