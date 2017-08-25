import "hash"

rule k3e9_15e14a961ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e14a961ee311b2"
     cluster="k3e9.15e14a961ee311b2"
     cluster_size="28 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['35ca6b8a74dcae91f4d949741c650d23', '0cf8512723619fa21b48ff44ceda54d4', 'b81aabb293f96a29da6d39984ac6c5f8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "2d0a794179422cbb47ac4f30a07f9908"
}

