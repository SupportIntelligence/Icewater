
rule n26e5_2b932ca6d3ab1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26e5.2b932ca6d3ab1916"
     cluster="n26e5.2b932ca6d3ab1916"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pemalform riskware malicious"
     md5_hashes="['f2422aa0b5ac08f5d536aff8217a1fd23f63e5a0','5dc27c43f676a74effb7d2e16c65044e67d5d712','546727b5e39a2b03bd742406d2011cfbe1831e7c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26e5.2b932ca6d3ab1916"

   strings:
      $hex_string = { ff83c404eb128b4b048d04bf2bf78bd68d0c81e82b97ffff8b43048d0cbf8d14888b4d088953080fb7018d7104668942ec0fb74102668942ee83c2f03bd67429 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
