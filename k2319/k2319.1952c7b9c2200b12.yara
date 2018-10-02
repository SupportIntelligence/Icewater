
rule k2319_1952c7b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1952c7b9c2200b12"
     cluster="k2319.1952c7b9c2200b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['8d51f0b57e75a97fa3483ca7ed7dc72f8c2e8a34','510bd44061258bec90ebed5493144e5b9e79970e','5e0e886fbf5a2c6397ba21e6f9d9a3745a1a2012']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1952c7b9c2200b12"

   strings:
      $hex_string = { 646566696e6564297b72657475726e20545b6c5d3b7d76617220463d28362e303345323c3d2830783143362c3532293f2839302c313333293a28307832342c38 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
