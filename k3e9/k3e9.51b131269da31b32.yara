import "hash"

rule k3e9_51b131269da31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b131269da31b32"
     cluster="k3e9.51b131269da31b32"
     cluster_size="82 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e414b663569a9fa85d4401f2ae63585d', 'dd18c59379a2f1db733619c1c98c596b', 'a1bd5cd64bc5a34dd898e1128386663a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "0d3081d09f971c3c9d786caf79ac8fb7"
}

