import "hash"

rule k3e9_51b13326d7a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13326d7a31b32"
     cluster="k3e9.51b13326d7a31b32"
     cluster_size="43 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['adbef5e3cb9cc3c5938878daa93b31e0', 'b24e2bd6428f76839aed51a29545d5ab', '69dd30f2f85f675288b3e9f9ffd18961']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,256) == "a770892bd678c7f454784a0c3e9f731c"
}

