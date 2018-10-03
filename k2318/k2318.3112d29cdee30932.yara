
rule k2318_3112d29cdee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3112d29cdee30932"
     cluster="k2318.3112d29cdee30932"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['235986054a5275eba76cd588b09ddd4d321a18bd','6925d702a4480c0b5fb449210e3793854856e91e','f4a5ee897822b49068207b8a8ae8261a07ebcc1e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3112d29cdee30932"

   strings:
      $hex_string = { 626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
