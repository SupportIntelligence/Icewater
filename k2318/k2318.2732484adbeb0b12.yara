
rule k2318_2732484adbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2732484adbeb0b12"
     cluster="k2318.2732484adbeb0b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['9ece3540fbf26ca86c718de08ea37667d70cc3c1','862c34c87c9c24bd57478b4fee3c1eb7317c2792','6a59d051aa70359e6ec2de3ad357172a459517ac']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2732484adbeb0b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
