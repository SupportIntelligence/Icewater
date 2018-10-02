
rule k2319_692d9699ca200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.692d9699ca200b32"
     cluster="k2319.692d9699ca200b32"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['de82b6fc31dfdbcfbdbc7259dee30042323ecf02','6d5507ffbd7d8b19dcaca31c9eb1a5d90d423aab','afc7ca842e265942f81e5763579f24a34bfac9df']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.692d9699ca200b32"

   strings:
      $hex_string = { 6566696e6564297b72657475726e20705b545d3b7d76617220563d282830783133342c36392e293e3d2831342e2c312e3033394533293f36312e3a307834423c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
