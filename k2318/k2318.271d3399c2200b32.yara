
rule k2318_271d3399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.271d3399c2200b32"
     cluster="k2318.271d3399c2200b32"
     cluster_size="4910"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['c8e4b66887ca650532fd88c96f2ee28b7b37d7f8','5558d9d26c3764c5969b481275e800cffdc046f4','1c69d53a00bc1ddfe583a0e80b7772182949ce7d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.271d3399c2200b32"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
