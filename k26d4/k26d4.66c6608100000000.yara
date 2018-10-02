
rule k26d4_66c6608100000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26d4.66c6608100000000"
     cluster="k26d4.66c6608100000000"
     cluster_size="148"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch malicious toolbar"
     md5_hashes="['5665e932467d9130c9d067238e18a04183ae6e61','ed8cfd93fdcca5be81fb29ce8ea132ea24ad6041','3a59df1cf23a108169bd76d20e1672e74a1e52f4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26d4.66c6608100000000"

   strings:
      $hex_string = { 74240c730d8b0685c07402ffd083c604ebed5ec3a1c830001085c0742f8b0dc4300010568d71fc3bf072128b0e85c97407ffd1a1c830001083ee04ebea50e84f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
