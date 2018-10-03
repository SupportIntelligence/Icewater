
rule k2318_375349adc6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.375349adc6210b12"
     cluster="k2318.375349adc6210b12"
     cluster_size="41"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['557bdb25310ba013beff9c656941c8823ec0d095','1352517a7af63aef2e48b36cc7ac178c6bcd64a3','b9d806b2bdacf75e64bd6a9110d47cf13a28cf00']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.375349adc6210b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
