import "hash"

rule k3e9_63146fb11c827b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fb11c827b16"
     cluster="k3e9.63146fb11c827b16"
     cluster_size="97 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a65f1b1ac455894ae4449f39565cb22c', 'f0889e31b1593950f40abd8b97a1cc53', 'dadbd6e318a7cd4a53912e6cf402f174']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

