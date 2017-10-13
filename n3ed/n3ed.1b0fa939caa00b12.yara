import "hash"

rule n3ed_1b0fa939caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b0fa939caa00b12"
     cluster="n3ed.1b0fa939caa00b12"
     cluster_size="313 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b4b148d0d9d411933f5878af6e76fff9', '0aef763e4c4226a05dff09e8871391a1', 'a513285a886dc16d6702c34e7047225e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(296995,1059) == "529f9aec791a33f80d7be972c607e7b7"
}

