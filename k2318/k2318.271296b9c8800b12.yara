
rule k2318_271296b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.271296b9c8800b12"
     cluster="k2318.271296b9c8800b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['6aa761a43c6f91084d4a4bd7d8c1a6cde2ef88d8','322197964b108c0899e0fb932ad202289b51145f','70d28d52e1c4e4e7a2fd6aa3b24b5c9c93a84225']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.271296b9c8800b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
