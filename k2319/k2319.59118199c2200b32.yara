
rule k2319_59118199c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.59118199c2200b32"
     cluster="k2319.59118199c2200b32"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['cad25409ef464aa933b206a7c801daa59975102f','7dea5bc26ba1582980015f70f979c6c0bcc1a9f7','2621e16e16a92f702a120e8a2028213beed01bd8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.59118199c2200b32"

   strings:
      $hex_string = { 425b595d213d3d756e646566696e6564297b72657475726e20425b595d3b7d76617220523d28283133372c3133392e293e39352e3f2830783234372c30786363 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
