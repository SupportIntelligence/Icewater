import "hash"

rule k3e9_3c1b3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1b3ac9c4000b14"
     cluster="k3e9.3c1b3ac9c4000b14"
     cluster_size="1893 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['540ced33503c3217e42ec912be26eee5', '1c2bef92a70303c4232a9aa6da6eead4', '5d914d36309b70c71c332b4c3913ed8c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "1371fd7f3206a21874fbe56ff62fb073"
}

