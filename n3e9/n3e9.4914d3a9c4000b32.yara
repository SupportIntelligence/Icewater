import "hash"

rule n3e9_4914d3a9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4914d3a9c4000b32"
     cluster="n3e9.4914d3a9c4000b32"
     cluster_size="615 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a6e5d62a1d5afe57e046f699e29d344d', '6ff85f6a60321a301c93525eabd1942c', 'af446781eeb6c3456350ae04d5393b8a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(3219,1097) == "9dbcdb80646b5cb4bf3285436fc29f56"
}

