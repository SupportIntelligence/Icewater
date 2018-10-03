
rule k2319_7b1abac1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.7b1abac1c8000b12"
     cluster="k2319.7b1abac1c8000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector html iframe"
     md5_hashes="['c9479ac1c7f44b82846fc94824456f7fcc0b6599','8e12c7338d53eb6d0ffca1ba83b90761f8e0947f','6b6bc5fcec4969c5aeefd15a76bc4310cc3fdf73']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.7b1abac1c8000b12"

   strings:
      $hex_string = { 6e673d22302220636c6173733d22626f785f77696474685f6c656674223e0a093c74723e3c74643e3c696d67207372633d22696d616765732f7370616365722e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
