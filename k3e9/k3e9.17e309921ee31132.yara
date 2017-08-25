import "hash"

rule k3e9_17e309921ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e309921ee31132"
     cluster="k3e9.17e309921ee31132"
     cluster_size="243 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['aebdaf63cd5ed6df28ed57235f8ff228', 'c0c4d5c8f0594dcf00baf78c2567e674', 'c0e0a3df69ad02c529c5c88d9f45bc7d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18432,256) == "10c0be3000134f23ee8f05667af0b64d"
}

