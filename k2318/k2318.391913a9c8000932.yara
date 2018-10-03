
rule k2318_391913a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.391913a9c8000932"
     cluster="k2318.391913a9c8000932"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['977691eb0458d7edb100386bffdb2f8d48823e60','68e4c7f7909a3a6d5f9065ad20dc7766b5bcc765','6c793ae1effc8430d56407fcd81fcbeece299c63']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.391913a9c8000932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
