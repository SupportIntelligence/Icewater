
rule k2318_2912529cdee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2912529cdee30932"
     cluster="k2318.2912529cdee30932"
     cluster_size="76"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['9f5063d00824ce7d3b94ca197ba34be0d3146de8','bfa17a75c686dc728c56258a4d509e5894ab9abd','0bc5ece9c2dbdd21fa71bd496c7ae9866a0d2807']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2912529cdee30932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
