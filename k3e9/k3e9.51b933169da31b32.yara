import "hash"

rule k3e9_51b933169da31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b933169da31b32"
     cluster="k3e9.51b933169da31b32"
     cluster_size="175 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b1da7d1d51d68be93ca010facb8482cf', 'c9bb5e0f93f3746293ad10b7f4a0531b', 'a3cc52d98e8e47f4915e8c1c6c5b3cb4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "0d3081d09f971c3c9d786caf79ac8fb7"
}

