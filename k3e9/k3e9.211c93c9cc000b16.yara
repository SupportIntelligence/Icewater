import "hash"

rule k3e9_211c93c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.211c93c9cc000b16"
     cluster="k3e9.211c93c9cc000b16"
     cluster_size="508 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b6b67627657411904f092b8a1a628f87', 'af0890a765a86981cfd3c143802a599d', 'a94de8b1df443c1f57c99cd03153e2ca']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(3072,256) == "7e5f6010306f5f419c4b32ea1a090954"
}

