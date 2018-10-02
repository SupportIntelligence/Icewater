
rule k2319_29194b99c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29194b99c2200b32"
     cluster="k2319.29194b99c2200b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['8204054a7c19671e515ee718a8fb52ed56548967','45e970491362ba46b9950ec21f437e4ac15f0194','4096ddfc799a0a15860da60a4b5dd314892fca2d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29194b99c2200b32"

   strings:
      $hex_string = { 6566696e6564297b72657475726e20565b6c5d3b7d76617220493d282830783138392c31372e304531293e3d283134312e3945312c33372e293f283078313642 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
