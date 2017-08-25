import "hash"

rule k3e9_50b133369da31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.50b133369da31932"
     cluster="k3e9.50b133369da31932"
     cluster_size="175 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9526e3b8368794191f7d3a8d97e7f8b6', 'a20978a679df9022114e4be950e3ad8c', 'ab2b658dee243311c6fb1bbba830d4b9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "8013aec142278ae2253a325ded189d2a"
}

