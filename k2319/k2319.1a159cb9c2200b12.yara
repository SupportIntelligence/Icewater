
rule k2319_1a159cb9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a159cb9c2200b12"
     cluster="k2319.1a159cb9c2200b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5264749f37b396a2e01bbe96aba4c92580b439e4','a0b56bdb2baca1ba7d3573d186ce53ffc0461a07','79c867645d0409c37e4f720cc3a96e82c3bf7430']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a159cb9c2200b12"

   strings:
      $hex_string = { 662862395b4c5d213d3d756e646566696e6564297b72657475726e2062395b4c5d3b7d76617220413d28372e343645323c3d2839332c372e324531293f38333a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
