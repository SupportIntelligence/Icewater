
rule k2319_311c96b9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.311c96b9c8800932"
     cluster="k2319.311c96b9c8800932"
     cluster_size="96"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik mplug script"
     md5_hashes="['9f90c98be0c435a0683f6d0824895b77b0c4e766','d49230f22f4834a9bf4838d6aa4ee6bce5ca2d1c','9c899c9d7f46396dd8affbca2bdf1c552f0121ef']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.311c96b9c8800932"

   strings:
      $hex_string = { 2836392e2c33352e364531292929627265616b7d3b766172204a3972383d7b27523952273a225758222c277731273a66756e6374696f6e285a2c75297b726574 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
