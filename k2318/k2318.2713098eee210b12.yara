
rule k2318_2713098eee210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2713098eee210b12"
     cluster="k2318.2713098eee210b12"
     cluster_size="260"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['75b9771fa9f2942084914cf85ee2ca3ca1ed985d','8eabd5c453bc18943d9b06df347de481dbfe77ca','97b8f471e853752183a53b3158a6f73ac6b5f6c6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2713098eee210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
