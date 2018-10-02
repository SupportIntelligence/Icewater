
rule k2319_3a54ea92d85a6b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a54ea92d85a6b12"
     cluster="k2319.3a54ea92d85a6b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script aknjt"
     md5_hashes="['37dfd499e23c46218332ec19cd42c5623a285614','d9f19d7b875928ae6f890dff76cd6b76e7aa9345','c9d786f8996a2d66a36c536123a68b6f11b1f534']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a54ea92d85a6b12"

   strings:
      $hex_string = { 4a5d213d3d756e646566696e6564297b72657475726e206f5b4a5d3b7d76617220723d282835392e2c39382e304531293e3d28307831372c38362e344531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
