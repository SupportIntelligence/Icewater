
rule k2318_33525512dfa30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33525512dfa30b12"
     cluster="k2318.33525512dfa30b12"
     cluster_size="57"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['f7e2ff63a33041c50ca45d5aa2396950090e2f15','8e5c892c49e9b9c007eb671bf8ef41a9eafd2afd','fe11d4fea42ce933ba1b3c61483f58525802e57f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33525512dfa30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
