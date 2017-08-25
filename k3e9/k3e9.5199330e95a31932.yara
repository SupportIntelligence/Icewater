import "hash"

rule k3e9_5199330e95a31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5199330e95a31932"
     cluster="k3e9.5199330e95a31932"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ba3d477c8c645857dfc9659f8c50553c', 'ba3d477c8c645857dfc9659f8c50553c', 'd1229f935e696b747fb907336f1eda97']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "f79c58d33e2db2633697540b31321cf1"
}

