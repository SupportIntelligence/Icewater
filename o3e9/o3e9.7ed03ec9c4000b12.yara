
rule o3e9_7ed03ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.7ed03ec9c4000b12"
     cluster="o3e9.7ed03ec9c4000b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock tdss nabucur"
     md5_hashes="['bf3850c12f2e950a49c59d4a43673395','c76a5d1bf3cf5ccc3edf83dcdcb08758','d0f0c07e90186aded31512c4a8ac7944']"

   strings:
      $hex_string = { f8d5b3fff5d3b2fff3d0b1fff0ceafffeecbaeffeccaacffebc8abffe8c5a9ffe5c2a8ffe3c0a6ffe2bfa5ffe0bda3ffddbaa2ffdab8a1ffdeae8fc6dfac8514 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
