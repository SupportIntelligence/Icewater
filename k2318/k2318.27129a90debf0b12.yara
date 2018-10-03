
rule k2318_27129a90debf0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27129a90debf0b12"
     cluster="k2318.27129a90debf0b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['9b770a16977526e252d0e6ce0ea0c54be25705e8','73e2cd5bbbcb873a0ca2745339e3b515d034b0e4','44feb79ee3099a69909e0b06a93c0c3ae891e0f3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27129a90debf0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
