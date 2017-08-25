import "hash"

rule k3e9_1e66a8d786620120
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1e66a8d786620120"
     cluster="k3e9.1e66a8d786620120"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bc26a3c63d1789bb533b55c41d5bfe26', 'bc26a3c63d1789bb533b55c41d5bfe26', '822a0912e5d2c329ee27d1c5e2c4d10a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "76f94909e41b2606eb664d22a535c8d2"
}

