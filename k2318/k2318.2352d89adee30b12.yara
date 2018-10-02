
rule k2318_2352d89adee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2352d89adee30b12"
     cluster="k2318.2352d89adee30b12"
     cluster_size="429"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['80eea9f556e9721535709a3cac1fc41469954ace','a5a5c8d10f6aefdbe193bccdb807b32e64322a9c','fb7801358058aa2a7f97c5057ddd1e294b00cbbc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2352d89adee30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
