
rule k2319_1b190399c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1b190399c2200b12"
     cluster="k2319.1b190399c2200b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['bd7de21d4348a2a9858c3381fb408a695382a4ad','590c853788cf658f606a4c5ca4ba2986d06713bd','3251d0a8542e88a1494d083675a3b7ee91e05c3b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1b190399c2200b12"

   strings:
      $hex_string = { 696e6564297b72657475726e204b5b475d3b7d766172204c3d2836382e313045313e28312e31383345332c313333293f2830783133412c307863633965326435 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
