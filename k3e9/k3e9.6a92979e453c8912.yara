
rule k3e9_6a92979e453c8912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a92979e453c8912"
     cluster="k3e9.6a92979e453c8912"
     cluster_size="51"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis malicious"
     md5_hashes="['055aec55759bc3e7db326d7d99861f57','1c63780c9d737b026c020232c43b3194','7964ea0c80aed5f6e466de9bcf7d1515']"

   strings:
      $hex_string = { c07c2b568d7041c1e6055703f18d78018b0685c07410837efcff750a50ff150430001083260083ee204f75e45f5ec3518b4424085355568b981408000057895c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
