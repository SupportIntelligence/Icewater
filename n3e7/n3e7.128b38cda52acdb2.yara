
rule n3e7_128b38cda52acdb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.128b38cda52acdb2"
     cluster="n3e7.128b38cda52acdb2"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="itorrent malicious unwanted"
     md5_hashes="['09089b19bf4c7d482e1b6e595d0e50b1','2bc07e570646e2ecf571574db1b8ec21','bbb1034475eba0ee78e4f3c093d9e1a5']"

   strings:
      $hex_string = { d6fb04e344744cfc311e9f524109a849d0de7dc589bb8a907cdf15075ff7be873ef6dccf2ed726e776cd5dfde0f2a9774d85e23914d57e6532f8aac4ffa283e6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
