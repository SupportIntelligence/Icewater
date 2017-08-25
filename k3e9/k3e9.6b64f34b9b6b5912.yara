import "hash"

rule k3e9_6b64f34b9b6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64f34b9b6b5912"
     cluster="k3e9.6b64f34b9b6b5912"
     cluster_size="19 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['8c96290d30d350a14cf1ead83cf5e823', 'a4785fc80bc748da69e5e64c9cfd39c0', 'cd9cbfd3137dfc76840fa35bad9a7e5a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6656,256) == "d5305026133f826ab69fb8f3889237bf"
}

