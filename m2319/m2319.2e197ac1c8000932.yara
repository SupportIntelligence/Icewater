
rule m2319_2e197ac1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2e197ac1c8000932"
     cluster="m2319.2e197ac1c8000932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script phishing redirector"
     md5_hashes="['72bd0949bf90bad928b9a98e4e24276c50ad837a','fc73430115869408b525bdfb66432feb7e45e56b','c91e4fd1a0cfd6daae90c5a93cf65d37f9979297']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2e197ac1c8000932"

   strings:
      $hex_string = { 75726c3d617267733b0d0a0909096e657720416a61782e526571756573742875726c2c207b656e636f64696e673a275554462d38272c6d6574686f643a202770 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
