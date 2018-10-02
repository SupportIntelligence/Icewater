
rule k2319_71359ab9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.71359ab9c8800b32"
     cluster="k2319.71359ab9c8800b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a2635638151b4e17ad3c43d85e4c28ba34a11f23','9dda798eb743a079e308a2a1059d1bb5801a71d5','ce37ae2a4ca4efc776c1c31b3b393d3145e060d5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.71359ab9c8800b32"

   strings:
      $hex_string = { 3a283078432c3078314231292929627265616b7d3b76617220713347313d7b27533950273a2242222c274934273a66756e6374696f6e28532c56297b72657475 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
