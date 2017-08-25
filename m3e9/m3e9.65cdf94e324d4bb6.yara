import "hash"

rule m3e9_65cdf94e324d4bb6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.65cdf94e324d4bb6"
     cluster="m3e9.65cdf94e324d4bb6"
     cluster_size="298 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['17fbd22c424969757005d4d988083db2', '8fba088ce8c3f1c38c02b2db16f29d6d', 'fa59a6380c5c168775e5897c4576e3c7']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(80384,256) == "97d3acaa4732eff4c8bdf0d777a5d813"
}

