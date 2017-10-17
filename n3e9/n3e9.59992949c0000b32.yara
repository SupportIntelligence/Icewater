import "hash"

rule n3e9_59992949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.59992949c0000b32"
     cluster="n3e9.59992949c0000b32"
     cluster_size="1456 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt manbat eyestye"
     md5_hashes="['6399ef0bdd99a8a625629d2141c42fc6', '4a9215a3d0ef775da3755a9e8c8f13f7', '17544f2d40dedce8f893b343df764f51']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(294912,1024) == "0075faf39e2f7d6fb77b0d07d4aeffbe"
}

