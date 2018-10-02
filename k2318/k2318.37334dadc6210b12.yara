
rule k2318_37334dadc6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37334dadc6210b12"
     cluster="k2318.37334dadc6210b12"
     cluster_size="96"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['1fe6623ffe179acb81951c8114991dd44f60c302','678324f91985d31c3a1e0feaf8406259272ae0a1','759663bcb66af283f894f20d9b4908322132123b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37334dadc6210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
