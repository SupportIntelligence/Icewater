import "hash"

rule k3e9_63b4b3c3d8a2d316
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b3c3d8a2d316"
     cluster="k3e9.63b4b3c3d8a2d316"
     cluster_size="28 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ac3bdad8a247949e6e201eac5516b39d', 'f4addc48817ce45196791ea8a9517fa2', 'ae4c58d21f8a216e8fe54a9ab3d15ed9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,256) == "fe88f5030104b15926c91a52764ce5e7"
}

