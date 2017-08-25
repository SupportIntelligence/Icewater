import "hash"

rule k3e9_17e30c871ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e30c871ee31132"
     cluster="k3e9.17e30c871ee31132"
     cluster_size="4 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a54203895054e4e11e55b372d6e3ae18', '7e25126ea28e54767a8226afde6adccd', 'a54203895054e4e11e55b372d6e3ae18']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "2fb80b5f3b6f045f2a5bf05d2c176dae"
}

