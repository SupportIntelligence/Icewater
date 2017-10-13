import "hash"

rule n3ed_31a4469982201132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a4469982201132"
     cluster="n3ed.31a4469982201132"
     cluster_size="104 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['98be6edf80dfe6d7fc5494eb70e85aa2', 'f59fdb0d274f1f5b1b43643338524694', '41203e201d1d30b4558fd2f5a2c63dc5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(286720,1024) == "21cd1f5dd6f252371e6aa6e53f74b815"
}

