
rule k2319_18518ce9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18518ce9c8800b12"
     cluster="k2319.18518ce9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['37a68550e069ce7489e4776b9b07c2224e1af695','fd037543f0b7cdb48ba4df3a486d6a6f7ca89aa2','d4711f2cb28619e70afd5ea7e0dc1017a36832e9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18518ce9c8800b12"

   strings:
      $hex_string = { 646566696e6564297b72657475726e206e5b755d3b7d76617220583d2828307836462c31332e39453129213d3133393f307835353a33342e3745313e2832322e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
