
rule k2319_295a8299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.295a8299c2200b12"
     cluster="k2319.295a8299c2200b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['cd55a8c0e9e7175412ffc7c2f57b0a192cc4b29e','c7a8699da63f3a628fe5d6e39ab6f87de0945eb8','06412653239c0be86607f43c09f4f5f866a6dd21']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.295a8299c2200b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20505b6a5d3b7d76617220753d28283132352e2c322e30374532293c3d283134362c3078323343293f2835332e2c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
