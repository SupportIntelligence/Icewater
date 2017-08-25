import "hash"

rule k3e9_519933169da31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.519933169da31932"
     cluster="k3e9.519933169da31932"
     cluster_size="50 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b87894f2da37bac3a8ffc2ca3b63a4ca', 'c79dd37b953c8a1a7207a6133b81ad8b', 'd443970c4394d91076710d1329807067']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "8013aec142278ae2253a325ded189d2a"
}

