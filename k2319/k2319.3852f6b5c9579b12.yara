
rule k2319_3852f6b5c9579b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3852f6b5c9579b12"
     cluster="k2319.3852f6b5c9579b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script kryptik plugin"
     md5_hashes="['7703ef0f8f0b8bf15c51bec9f5a56f4cd508c983','72a56a075226c04d3283ce2107f90e703917e87e','1cc3b0872de44895f5fec958432dde87c0cf1384']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3852f6b5c9579b12"

   strings:
      $hex_string = { 6566696e6564297b72657475726e207a5b485d3b7d76617220543d282832322e3345312c37332e334531293e3d3130372e3f2831342e2c307863633965326435 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
