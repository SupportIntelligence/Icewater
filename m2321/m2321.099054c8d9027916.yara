
rule m2321_099054c8d9027916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.099054c8d9027916"
     cluster="m2321.099054c8d9027916"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="filetour zusy jacard"
     md5_hashes="['18b281e4b0a123349a1267a67866cdd3','295597bc45f5d2ef3b5a6a95df0b0f43','e439413e8d3a2da11efc2c2a4118d546']"

   strings:
      $hex_string = { d068b22fd7a479c3e470325aa1aed16c0792bc40125f0d9c2481152c1fc17d82f5628edb41f81805cd2aed394742aa547ad373bf11dfc000d92db5e1a284c465 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
