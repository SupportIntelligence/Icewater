
rule k2318_3919b2b9ca800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3919b2b9ca800932"
     cluster="k2318.3919b2b9ca800932"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['b07d1b30bde77859a049abb968e16f33da7845a1','6f6d7dfeec20c149bafc44fbbc41972390fa420a','f6db5a2fcfbe2388559e565aefcfc72b4de3fbac']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3919b2b9ca800932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
