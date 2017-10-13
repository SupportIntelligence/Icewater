import "hash"

rule n3e9_396c9299c2220932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.396c9299c2220932"
     cluster="n3e9.396c9299c2220932"
     cluster_size="86 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="lethic strictor trojandropper"
     md5_hashes="['3589a5b802e7cd5dedc72140ec1f7bf1', '8886301f0bf02c84d27e335e597fba1f', 'a919b4bc671d5f171f3fd12ec96f6f5d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(173056,1024) == "ce2f94dc96e8f8bf8f5033bdc78bde37"
}

