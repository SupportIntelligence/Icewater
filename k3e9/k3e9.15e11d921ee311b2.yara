import "hash"

rule k3e9_15e11d921ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e11d921ee311b2"
     cluster="k3e9.15e11d921ee311b2"
     cluster_size="40 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['abcc654cf9421861939d68bda1dd5681', '5e201dd433c4e77752c50d486aa8933f', 'b1fc2f7844ecd50306ea4e879cab9172']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "2d0a794179422cbb47ac4f30a07f9908"
}

