
rule p26d7_2b9bb949c0000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26d7.2b9bb949c0000916"
     cluster="p26d7.2b9bb949c0000916"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="softpulse malicious digitalplu"
     md5_hashes="['3f41872b036d667379aa3cc1d4e44827b5a0bb30','1b3fd2f29f8f87ae5f0caea4863caaa577658f3a','1d14d50e578d7fba08ce789180baa68cd28abf09']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26d7.2b9bb949c0000916"

   strings:
      $hex_string = { ccf3ab59a1604f840033c5508d45f464a300000000894df08b450883380374116a5f68e0277c00e8d290faff85c07401cc8b55080fb7420c8945ec837decff75 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
