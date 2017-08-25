import "hash"

rule k3e9_3c183ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c183ac9c4000b14"
     cluster="k3e9.3c183ac9c4000b14"
     cluster_size="909 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['3cb5c44bd78c432628086efccdbcd950', 'a6ff4dfa41e7d876533c2ee3fe0a0b05', '3c67e64b61715262f4c4cbd1dcc950fd']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "1371fd7f3206a21874fbe56ff62fb073"
}

