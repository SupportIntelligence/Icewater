import "hash"

rule m3e9_2d96cb26ea408932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2d96cb26ea408932"
     cluster="m3e9.2d96cb26ea408932"
     cluster_size="67 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b0378423311c804a8526453c8d217908', 'c60435a850efe5979f40eb5ddc4c209d', '27663b685db6ca2ac36b568235d2db07']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73728,1024) == "d0d038130aeb82cf87189ddf5ec47c53"
}

