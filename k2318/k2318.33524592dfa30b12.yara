
rule k2318_33524592dfa30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33524592dfa30b12"
     cluster="k2318.33524592dfa30b12"
     cluster_size="269"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['9f8f29b32e87d1c7434d7d372366b8ae608f42fe','cb44ce056df9f3e36fdae71081ef8016d91c6c53','22ba0d6be4d3795878c3d14e1d6e0a89d0650a67']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33524592dfa30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
