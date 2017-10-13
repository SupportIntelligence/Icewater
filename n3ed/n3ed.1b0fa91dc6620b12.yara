import "hash"

rule n3ed_1b0fa91dc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b0fa91dc6620b12"
     cluster="n3ed.1b0fa91dc6620b12"
     cluster_size="407 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['c6eb8bf8b2192ddbc55c30b000885000', 'c78740b37312d3703c750af22363cd07', 'bfe2d1c30f6359a623ee16d420cce3a8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(296995,1059) == "529f9aec791a33f80d7be972c607e7b7"
}

