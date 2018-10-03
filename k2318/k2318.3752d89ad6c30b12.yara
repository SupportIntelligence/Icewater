
rule k2318_3752d89ad6c30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3752d89ad6c30b12"
     cluster="k2318.3752d89ad6c30b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['1f0b6cc9e7f7943a76ea646a42077873c6a12588','203d5034e0f1802f37900f124933cba40a328fa7','b4fb15250ce4717d5d70fd7b42ee45f0516e68c9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3752d89ad6c30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
