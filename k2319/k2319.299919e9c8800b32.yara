
rule k2319_299919e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.299919e9c8800b32"
     cluster="k2319.299919e9c8800b32"
     cluster_size="420"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['51f2816dac689daa98b74d8c5c617a134deaac0d','38fae89ea0b886265e2f02fae3ba57deccb0d87a','3910580ca4b2512eb86371a8c59dc5b16fb870d4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.299919e9c8800b32"

   strings:
      $hex_string = { 6d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443e50 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
