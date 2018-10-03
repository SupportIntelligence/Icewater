
rule k2318_2152d38bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2152d38bc6220b32"
     cluster="k2318.2152d38bc6220b32"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['97c4a714e0fd6931bef2ae751d196b7a7a47b487','4c28818ef2a80b6f6ea0121fe1c07deac5155b90','300cfb43dc0b3a392c37bda69acbfb83dd94da80']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2152d38bc6220b32"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
