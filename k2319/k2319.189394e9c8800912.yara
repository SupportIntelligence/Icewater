
rule k2319_189394e9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.189394e9c8800912"
     cluster="k2319.189394e9c8800912"
     cluster_size="50"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem expkit"
     md5_hashes="['b49d881519e58b45c11297a5b599672083c52033','42f49d8fabb0323e3707985be142130bf1a6225b','395b5dfd704b177787bbc4c826e7de66e20f33ba']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.189394e9c8800912"

   strings:
      $hex_string = { 6566696e6564297b72657475726e204e5b525d3b7d76617220483d282834392e2c312e3033314533293e3d307846433f2830783144312c307863633965326435 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
