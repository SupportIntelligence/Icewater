
rule k2318_31197ac1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.31197ac1c8000932"
     cluster="k2318.31197ac1c8000932"
     cluster_size="719"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['bcc9b5a585953f91eb11117376eca8e91a8c18e4','40e501df42913ac0b2580f855906b85b05e98353','4227f728c8ead5a9f173eb6f6c2b631317df6d2d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.31197ac1c8000932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
