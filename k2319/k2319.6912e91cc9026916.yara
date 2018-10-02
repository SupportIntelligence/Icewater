
rule k2319_6912e91cc9026916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6912e91cc9026916"
     cluster="k2319.6912e91cc9026916"
     cluster_size="2257"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script flooder html"
     md5_hashes="['bfbedcf120357beb2546a30b26c1f5d311f03c01','14c19e4fea262fcf77780bd6a051a77c123cd3e0','dbfe0d3784c3fa9ed34db188baeeadaed3566461']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6912e91cc9026916"

   strings:
      $hex_string = { 2e636f6d2f696d616765733f713d74626e3a414e643947635467303977335932784858537645624774776332664f3435537538366a5a48692d75625033705155 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
