
rule k2318_311a53c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.311a53c9c8000932"
     cluster="k2318.311a53c9c8000932"
     cluster_size="213"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['6d48f97da8c244ec839714d16e787d77f1d5b510','73e9d9248d4ebb598d86dc7b7daeab4bdae2813c','1be358eadb4ac8f47c7ee14c2d5d3feb230798c3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.311a53c9c8000932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
