
rule k2318_27535246cbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27535246cbeb0b12"
     cluster="k2318.27535246cbeb0b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['2ffb7e65de0e80ae23b6a15c427e6466c8210dbc','a9298e9b72b81be84270326672fabdfa3b16924e','ad1ae63ad6c44b8751d3ed09a55f023ab183b012']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27535246cbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
