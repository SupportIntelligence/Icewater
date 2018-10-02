
rule k2318_2711212eae210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2711212eae210b12"
     cluster="k2318.2711212eae210b12"
     cluster_size="111"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['51292a721eb04d0e7aa8f7618c52c53dc3ae5e37','bcc8c6ba9d0655a08e1f45297b07e17d4aafd546','ff3e855ee400b20e68e614cfc59cf2fc0fd0dd22']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2711212eae210b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
