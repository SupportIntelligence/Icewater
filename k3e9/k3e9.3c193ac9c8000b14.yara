import "hash"

rule k3e9_3c193ac9c8000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c193ac9c8000b14"
     cluster="k3e9.3c193ac9c8000b14"
     cluster_size="576 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['34b98464d385d75f5637dfe097f9dea9', 'b36ccbb6f227af3292fffab4869d445f', '565038d246cc58ffb35c891c4c984ae1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "1371fd7f3206a21874fbe56ff62fb073"
}

