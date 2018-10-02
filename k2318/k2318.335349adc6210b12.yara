
rule k2318_335349adc6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.335349adc6210b12"
     cluster="k2318.335349adc6210b12"
     cluster_size="163"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redir"
     md5_hashes="['49de64348e4182c672558c64d52ecd10a317d35d','29e8c41522cf3f2ad111cd75392f4e4b61fdb162','0bdef162d9917fe0a13a905a5397bf1f85406b97']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.335349adc6210b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
