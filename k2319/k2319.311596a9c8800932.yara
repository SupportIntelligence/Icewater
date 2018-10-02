
rule k2319_311596a9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.311596a9c8800932"
     cluster="k2319.311596a9c8800932"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['28bdd8b1d4d2fd21456bf51b20a3604aa284dd81','d9e3df5ccb924daf08f0e46c046c1961ddf6c3a4','c27952779ba02c53cbe43652f962ce39912ad51c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.311596a9c8800932"

   strings:
      $hex_string = { 42333f2834302e3545312c313139293a2830783145442c31342e30384532292929627265616b7d3b76617220433949373d7b276830273a66756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
