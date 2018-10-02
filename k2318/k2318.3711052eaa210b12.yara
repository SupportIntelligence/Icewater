
rule k2318_3711052eaa210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3711052eaa210b12"
     cluster="k2318.3711052eaa210b12"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['b6fa7365eac66b97f816654b8b7e6f4568f3c1ef','ee3804c6f6ed29052c40a1538a8d461dd2e9cd29','210ad8d63870189261b4e4efddb2006b17f956f0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3711052eaa210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
