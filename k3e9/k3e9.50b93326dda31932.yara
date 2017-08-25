import "hash"

rule k3e9_50b93326dda31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.50b93326dda31932"
     cluster="k3e9.50b93326dda31932"
     cluster_size="14 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c85014e715feb39c6613259994bbce05', 'c44f9fb74600409a4dc11aec172a243a', '3e555875774ce30f5fcfa3862b07f36e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "f79c58d33e2db2633697540b31321cf1"
}

