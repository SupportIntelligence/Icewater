
rule k2318_2912d22b97a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2912d22b97a30932"
     cluster="k2318.2912d22b97a30932"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['1aee11bbc9dfa90280231472b68aeabb66a6d7ba','2eb39c6328cc9c7b93b3137761db8325a48c6593','d5d0308e999344b59c7dfd8c93a0a30fd8b09902']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2912d22b97a30932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
