
rule k2319_391456b9c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391456b9c6220b12"
     cluster="k2319.391456b9c6220b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6a481eab8730b33420e03d150afbc14487d140d6','64bcfd8e8b8f6cafe8e54322f9c2592ff04a8148','9d77d6005efc6054543cae69fc8efde01741b0a3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391456b9c6220b12"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e20475b6f5d3b7d76617220433d2828307846442c392e37324532293e2830783137392c39352e36304531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
