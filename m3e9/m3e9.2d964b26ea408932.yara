import "hash"

rule m3e9_2d964b26ea408932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2d964b26ea408932"
     cluster="m3e9.2d964b26ea408932"
     cluster_size="107 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b3e36893e5c2ad979c9ad42b7800c43c', 'b49b36edf2b17cf14e7f06560f439f0c', 'a67c147ccf4cfa746fe84d818970d6d3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73984,256) == "c4579ae7d6ad98313b9305c7221f73ef"
}

