import "hash"

rule k3e9_15e10d921ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e10d921ee311b2"
     cluster="k3e9.15e10d921ee311b2"
     cluster_size="120 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['7f4c80bdfa716358a8f596618a44e624', 'f4c24f696dba85122d7d092bfd911496', '6c85e075e881714cd368f8de6274d450']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "479d8ddd4ba5d72b0f7fc8167a804cd4"
}

