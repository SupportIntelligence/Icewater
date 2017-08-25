import "hash"

rule k3e9_51b93326dda30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93326dda30b32"
     cluster="k3e9.51b93326dda30b32"
     cluster_size="144 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d14cd21d0c46b4aee4b2c703ca7ef120', 'c41da8d608fc34cf5b3a45a35f2a0c39', 'ae77d2e60e5d18a0688f59e7d674c571']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

