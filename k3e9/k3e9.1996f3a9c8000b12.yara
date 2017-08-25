import "hash"

rule k3e9_1996f3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1996f3a9c8000b12"
     cluster="k3e9.1996f3a9c8000b12"
     cluster_size="19 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="backdoor razy injector"
     md5_hashes="['b4b3f683eaee4e10f9c975ac00a43892', 'b33dc98881d4e159016035a34fb06035', 'a5e71a0eb3946ef7e31fed7c8a63de09']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

