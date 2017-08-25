import "hash"

rule k3e9_6b64f34b8a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64f34b8a4b5912"
     cluster="k3e9.6b64f34b8a4b5912"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['dae4ef368ac20b1736055e61c8bd7e8f', 'c47db54fabf371685155d394b383e2fa', 'd9162fb2165b7992a2a48359ae0f7e67']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6180,1036) == "2b4289c8af774f0b1076619ad1925bff"
}

