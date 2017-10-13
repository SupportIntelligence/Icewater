import "hash"

rule k3e9_6b64d34b0b6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b0b6b5912"
     cluster="k3e9.6b64d34b0b6b5912"
     cluster_size="122 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['b443c6a00a78216ba4878ba8cada1bca', 'a4c5b521ac4f98acc40894b74b3344b5', 'dfb56b61bc874233579872fc5e748a3d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(11360,1036) == "344675ffeadac8a29fb9e31d1c7725a6"
}

