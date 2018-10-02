
rule k3f8_6db93d2f46221110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.6db93d2f46221110"
     cluster="k3f8.6db93d2f46221110"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos asacub"
     md5_hashes="['13f841325430955e9f09cc717ece5dfb9998d535','b16347e2fd9e52eb1f3e6253f78e662fc10ca832','301d16d17dd5476b86c7fa10a0dfabe9378f88ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.6db93d2f46221110"

   strings:
      $hex_string = { 7461626173652f437572736f723b00114c616e64726f69642f6e65742f5572693b001a4c616e64726f69642f6f732f4275696c642456455253494f4e3b00124c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
