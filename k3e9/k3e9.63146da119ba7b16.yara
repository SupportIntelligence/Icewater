import "hash"

rule k3e9_63146da119ba7b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da119ba7b16"
     cluster="k3e9.63146da119ba7b16"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['8baa6914cc7218d5ab986b9b6dc5eccc', 'c431a2a3e471d026738d240eddc70fbe', 'bab4dddb3bb190fa71190040e044426a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

