
rule k2319_295496a9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.295496a9c8800b32"
     cluster="k2319.295496a9c8800b32"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b6ca8b15993188ac2430d244d621eea0c8cf3dbd','c792c73cbc6c6296c3e9bfcc776008085e5edf2c','b454fbd8097adcea1949fad26bf39a78c9cc3da3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.295496a9c8800b32"

   strings:
      $hex_string = { 646566696e6564297b72657475726e206c5b515d3b7d76617220573d282830783144332c322e34314532293e3d283132362e2c312e3434374533293f3330303a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
