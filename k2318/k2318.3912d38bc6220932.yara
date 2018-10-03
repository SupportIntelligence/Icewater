
rule k2318_3912d38bc6220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3912d38bc6220932"
     cluster="k2318.3912d38bc6220932"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['bc6f1e7a83791c5ed347399a12ccd613f1b5a0b8','2baac25aa3a0146c4ac81f808d08778841259a07','6a2401d3db88d1ab079805eb9aad02b20cf4710c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3912d38bc6220932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
