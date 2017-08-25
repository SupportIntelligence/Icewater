import "hash"

rule k3e9_1e1e9899c2200b28
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1e1e9899c2200b28"
     cluster="k3e9.1e1e9899c2200b28"
     cluster_size="20 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e2a89570340bda26dda727f2cf136825', 'a264da2786378705953273178b31b478', 'cd3d37f5c502d501ac355c8b5140f131']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9228,1024) == "3cd74ec5a97434d76724b507d80be74e"
}

