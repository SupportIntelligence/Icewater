
rule k2318_2912530bd5a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2912530bd5a30932"
     cluster="k2318.2912530bd5a30932"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['2674382e723d5755e982e5ae380793b02a9a6f0d','a477c2cda647454c4a810ffe5c57e03300da0201','d8d7d90fa778bc0c8c981115a4569e73fe9c5296']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2912530bd5a30932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
