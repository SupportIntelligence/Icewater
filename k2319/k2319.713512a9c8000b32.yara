
rule k2319_713512a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.713512a9c8000b32"
     cluster="k2319.713512a9c8000b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['ab9358e409c1fbe156cbd49b3f8d95e904dc6c7a','86ae3b0bc84e144c56988cf0ce620f3126c8054d','d407f0e5143f7ad3a8daf972d6b602b3f23e523f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.713512a9c8000b32"

   strings:
      $hex_string = { 3a283078432c3078314231292929627265616b7d3b76617220713347313d7b27533950273a2242222c274934273a66756e6374696f6e28532c56297b72657475 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
