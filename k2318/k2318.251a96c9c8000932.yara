
rule k2318_251a96c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.251a96c9c8000932"
     cluster="k2318.251a96c9c8000932"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['a00e504eaa4ab4154d60ad7094b6f0cfa2ec11a6','a85988a9e03c2326207d51ab1acde2eba52f153a','fa6c40e61451906630c54c5bf2cd34d4bfde4e57']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.251a96c9c8000932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
