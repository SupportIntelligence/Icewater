
rule k2318_311b4acdea200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.311b4acdea200932"
     cluster="k2318.311b4acdea200932"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['3808901dcc39c00595b10151eab89e5da517b582','cd242699eb3659b70aeeb53c99764dd4d2f30ade','6d6bc8d8cfe0aa45fd1b3ce5e0606c66baa9efbb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.311b4acdea200932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
