import "hash"

rule k3e9_6b64d36b994b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b994b5912"
     cluster="k3e9.6b64d36b994b5912"
     cluster_size="188 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['d0f93d8a4f220e94b5ad7a659294ca56', 'de113e5bed3d1775a92665e47ff95e03', '442b8d0d6428d7fdbe47ee03cdbb845e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "b99b5cf10e3c3d9af872a74a92ecec2b"
}

