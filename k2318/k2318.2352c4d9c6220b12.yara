
rule k2318_2352c4d9c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2352c4d9c6220b12"
     cluster="k2318.2352c4d9c6220b12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['a6139bfe57428653e074367bf1fec3361469a51a','58fbe0c9b92fa2704b0a6154967959a792bf7f6d','6bcc69c296ceef21ccde47f3d132c4f494a5a07e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2352c4d9c6220b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
