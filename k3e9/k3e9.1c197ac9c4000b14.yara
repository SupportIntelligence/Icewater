import "hash"

rule k3e9_1c197ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1c197ac9c4000b14"
     cluster="k3e9.1c197ac9c4000b14"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="simbot backdoor razy"
     md5_hashes="['b4d3c7844d98723462a832d1c66f4aa4', 'b4d3c7844d98723462a832d1c66f4aa4', 'a544d64b90b6cd69ce894294650b983b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

