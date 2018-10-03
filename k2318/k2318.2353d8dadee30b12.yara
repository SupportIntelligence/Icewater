
rule k2318_2353d8dadee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2353d8dadee30b12"
     cluster="k2318.2353d8dadee30b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['3952887a6b5af6b8fa4d7c87ac1cac9934932640','cff5556c5b47702d3e69964583d834667dc99b16','06c810bc8daf7c972ec93d9d21ef88da32e63c69']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2353d8dadee30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
