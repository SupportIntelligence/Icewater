import "hash"

rule m3e9_63183ac1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.63183ac1cc000b12"
     cluster="m3e9.63183ac1cc000b12"
     cluster_size="432 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack backdoor"
     md5_hashes="['ac553d8e2bea55e08c6ebb92d6272f2d', 'aba4adfa5744c5b8b193549e3647bf04', 'a2ffad0c38715b3d6610e3c49fbeab0f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

