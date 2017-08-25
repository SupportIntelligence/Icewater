import "hash"

rule k3e9_329b94dadec31b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.329b94dadec31b16"
     cluster="k3e9.329b94dadec31b16"
     cluster_size="56 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['f3f316fd691b8c3dd3c629c318115bd1', 'a2debba1a3349d5920cfaf7ef02d4345', 'cbb23b5a4a1b1d443604f06caedf1e57']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,256) == "cc66ac3c5629854ed877c268c081b668"
}

