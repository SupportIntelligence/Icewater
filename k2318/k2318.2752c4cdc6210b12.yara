
rule k2318_2752c4cdc6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2752c4cdc6210b12"
     cluster="k2318.2752c4cdc6210b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['1508d8c77a458e210967e9ebddc4b7929016eee0','08be3975eb06e4593e0c05485948d3ef1636e40d','c39a65a7db936c40e4394fd3ee60394c069dd123']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2752c4cdc6210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
