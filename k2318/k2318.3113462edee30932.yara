
rule k2318_3113462edee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3113462edee30932"
     cluster="k2318.3113462edee30932"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['8d7b36cd3543c70214422e89f8846e7d41930667','03a85bae5d638bf32b8575b9b0763c4918b25729','90a3ef633edd98ac63e33b26d039a98ab7564cf5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3113462edee30932"

   strings:
      $hex_string = { 626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
