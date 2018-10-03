
rule k2318_3998d6b9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3998d6b9c8800932"
     cluster="k2318.3998d6b9c8800932"
     cluster_size="116"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['13e5784a203da95bc904a7a65d07622c27ca9504','05e916af5ed0acd836fef47ab15b55280ab43a93','fd5c624975d630866fbaad825eb57b4192a1dd28']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3998d6b9c8800932"

   strings:
      $hex_string = { 626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
