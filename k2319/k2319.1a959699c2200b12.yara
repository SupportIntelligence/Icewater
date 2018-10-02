
rule k2319_1a959699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a959699c2200b12"
     cluster="k2319.1a959699c2200b12"
     cluster_size="137"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['3da2172ad4169b316ab08bb00ea1175397cfd301','7e09d85c71ea32b3b817985bf786037736efd932','5a149351236b54e5f6af752868999bd8230c7144']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a959699c2200b12"

   strings:
      $hex_string = { 4e5d213d3d756e646566696e6564297b72657475726e20725b4e5d3b7d76617220573d28307834343c283134302e2c352e30334532293f2836382c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
