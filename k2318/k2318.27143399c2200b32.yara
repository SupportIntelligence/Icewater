
rule k2318_27143399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27143399c2200b32"
     cluster="k2318.27143399c2200b32"
     cluster_size="8025"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['274effefe258353aab6d253609ebc96cd9b692de','41cfd097daa0f6731d29c7a2f61cedfb234ff7d6','6916f9c4df5b0541550b72f158edbf1338440bf1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27143399c2200b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
