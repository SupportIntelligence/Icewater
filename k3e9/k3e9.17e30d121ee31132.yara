import "hash"

rule k3e9_17e30d121ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e30d121ee31132"
     cluster="k3e9.17e30d121ee31132"
     cluster_size="31 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d13585f0048b607bbf2122c203d9b7ad', '885ace30931adb056195bbf7a5b3ee05', '5ffadb62ce93c1378a43e4586b8bbf40']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "479d8ddd4ba5d72b0f7fc8167a804cd4"
}

