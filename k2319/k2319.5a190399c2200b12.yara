
rule k2319_5a190399c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a190399c2200b12"
     cluster="k2319.5a190399c2200b12"
     cluster_size="51"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['cc444594de65ba4c16ad98bfdf97ef69eaab4023','6004b6b167e8dfc2bc543191fb0e25885883e5fc','86503c90658fc02da057a89d1400cc4035143c06']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a190399c2200b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20455b4a5d3b7d766172204f3d2828307843422c312e313430304533293c2837302e363045312c3235293f2754273a28332e38 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
