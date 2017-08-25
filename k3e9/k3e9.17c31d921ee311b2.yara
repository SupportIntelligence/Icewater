import "hash"

rule k3e9_17c31d921ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17c31d921ee311b2"
     cluster="k3e9.17c31d921ee311b2"
     cluster_size="6 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e21080c0e440a17624fd1d8b2a9735ea', 'e21080c0e440a17624fd1d8b2a9735ea', '51ac18aff0308865d888dc16faafd43c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "c90aa5f283c5cb7bd8e6ffdf6a121846"
}

