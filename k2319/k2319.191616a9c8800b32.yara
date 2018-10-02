
rule k2319_191616a9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.191616a9c8800b32"
     cluster="k2319.191616a9c8800b32"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['0546096983340b77abfa2901ee5bc6c4574602a5','4e04ee8aa1fda912425b10e2d2b7d30be0cd4a7c','57b9e35d750bc815ee2f5d5eb07cdaba253e883f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.191616a9c8800b32"

   strings:
      $hex_string = { 66696e6564297b72657475726e20765b4b5d3b7d766172204e3d28283133372e2c33372e293c3d307843433f2836382e2c30786363396532643531293a283132 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
