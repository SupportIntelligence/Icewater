
rule k2319_71351ab9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.71351ab9c8800b32"
     cluster="k2319.71351ab9c8800b32"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem expkit"
     md5_hashes="['91279b93ec2be7e1447538f6ad28e223ad3e3943','5895792125b4677fd8a091e4d23fab743a93665d','f30e25198df6978e2000ce6a688e546ede64ea78']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.71351ab9c8800b32"

   strings:
      $hex_string = { 3a283078432c3078314231292929627265616b7d3b76617220713347313d7b27533950273a2242222c274934273a66756e6374696f6e28532c56297b72657475 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
