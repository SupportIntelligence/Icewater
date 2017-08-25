import "hash"

rule k3e9_3c143ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c143ac9c4000b14"
     cluster="k3e9.3c143ac9c4000b14"
     cluster_size="193 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['a6cc2d3975f80877c73cf207e591c34f', '8f092ca3a8930a26faffb9842922f1ca', 'b702ece29d0b5d2ce088a8df6d27af0c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "1371fd7f3206a21874fbe56ff62fb073"
}

