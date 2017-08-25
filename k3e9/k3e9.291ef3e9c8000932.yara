import "hash"

rule k3e9_291ef3e9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291ef3e9c8000932"
     cluster="k3e9.291ef3e9c8000932"
     cluster_size="106 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="backdoor razy simbot"
     md5_hashes="['376a7e736c8f85f8b0d8aceca0149cbd', 'ac6c9b2b90f61582cbff4bff8e8d1ab0', 'ca4ac588d4e2921309692f8b497a0b66']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

