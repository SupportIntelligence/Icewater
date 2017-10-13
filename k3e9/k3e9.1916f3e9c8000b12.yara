import "hash"

rule k3e9_1916f3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1916f3e9c8000b12"
     cluster="k3e9.1916f3e9c8000b12"
     cluster_size="71 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['0f42e23b6f34a660de5a8c7062ded5c5', '0e5ad91b2ee5be947dfb3ef76f5cb0ad', '31be2da0bc07cf84f18c7d792d127369']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

