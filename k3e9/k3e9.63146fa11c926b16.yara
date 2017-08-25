import "hash"

rule k3e9_63146fa11c926b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fa11c926b16"
     cluster="k3e9.63146fa11c926b16"
     cluster_size="85 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bd847ce1f5048a66ebf2566438cb3a88', '1305e956dca3d7422a750180ca144780', 'c337873d371ee1b4fbc91ed57df8c461']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29184,256) == "2e1e953ff8b0c4afd8a93f50be9aa1f2"
}

