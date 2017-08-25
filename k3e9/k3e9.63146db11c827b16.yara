import "hash"

rule k3e9_63146db11c827b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146db11c827b16"
     cluster="k3e9.63146db11c827b16"
     cluster_size="24 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['395d1223de44d8c17885d31cc5ec790b', 'f99f21a0742536a406a726c56205fa4c', 'a5bb5abca25a21c69395c7b921f2ef10']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29184,256) == "2e1e953ff8b0c4afd8a93f50be9aa1f2"
}

