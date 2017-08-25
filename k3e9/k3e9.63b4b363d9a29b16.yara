import "hash"

rule k3e9_63b4b363d9a29b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d9a29b16"
     cluster="k3e9.63b4b363d9a29b16"
     cluster_size="30 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a0ed2632c8ceeed8825d8614310aa6b9', 'b05935e22c858eec7cc1b6e5a2ad73f3', '9dc58bf63d2508752666566ee58f3d53']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,256) == "fe88f5030104b15926c91a52764ce5e7"
}

