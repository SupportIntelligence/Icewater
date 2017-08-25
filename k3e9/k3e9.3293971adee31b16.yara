import "hash"

rule k3e9_3293971adee31b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3293971adee31b16"
     cluster="k3e9.3293971adee31b16"
     cluster_size="84 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b5b0b6039870bc4e95edf6a68935286d', 'be3d166d3e64fc422f5fa3f949a91749', 'd9280279cd00bbf4df2b99e1071b2f9f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,256) == "cc66ac3c5629854ed877c268c081b668"
}

