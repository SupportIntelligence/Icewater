import "hash"

rule k3e9_51b93316d5a30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93316d5a30932"
     cluster="k3e9.51b93316d5a30932"
     cluster_size="43 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ef512b4398845e6baeb9a9abff281b43', 'b739a7cfa29731736747944ae1083a86', 'bd7a1cc951008b6156a76266c0726603']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "0d3081d09f971c3c9d786caf79ac8fb7"
}

