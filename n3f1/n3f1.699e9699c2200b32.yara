
rule n3f1_699e9699c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.699e9699c2200b32"
     cluster="n3f1.699e9699c2200b32"
     cluster_size="18"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="obfus androidos andr"
     md5_hashes="['03bad665c10c64299fe4d31ad417125f','0997b919b5d5fa662af7a728e295d984','f31fa1b4b99a020c77d3e3c799f80635']"

   strings:
      $hex_string = { 07803b0db5c6d0986d168a29f57d9a05096e5aadaa6a9b82340c657d7fbfd96c589c99558b59d72ef6e63fdaf81637cdbb8dce17e8fa568e1ec06f4c25f2141b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
