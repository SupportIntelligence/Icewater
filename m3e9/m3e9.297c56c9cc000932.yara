import "hash"

rule m3e9_297c56c9cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.297c56c9cc000932"
     cluster="m3e9.297c56c9cc000932"
     cluster_size="264 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d64c603a7c1d4b7d47ecbeae6d76f262', 'bb9bdd94f666ceb591702e3270b17d2d', '9de485b945db0bd2db6c1205d1700450']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(7552,1088) == "2db6a2f628f1b4640a72420586ffb011"
}

