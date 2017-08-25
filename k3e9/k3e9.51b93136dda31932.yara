import "hash"

rule k3e9_51b93136dda31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93136dda31932"
     cluster="k3e9.51b93136dda31932"
     cluster_size="133 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b8298266bcb961e109bf1bdaff9cd683', '95ec70afa9bbcb71fba7544a584dd2b7', 'c13a1282858ae52fd55ea3f62e9fe133']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,256) == "286a6db30376a984ee1706d41700b1f3"
}

