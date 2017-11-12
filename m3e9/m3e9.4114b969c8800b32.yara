import "hash"

rule m3e9_4114b969c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4114b969c8800b32"
     cluster="m3e9.4114b969c8800b32"
     cluster_size="217 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['383a5d90c9fcf22a0282c94a271c380c', '7a430c1e34eff679b20fa1cf6a1a9c06', 'e334b6161481348f7cf24e2a7fd79daa']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(81408,1280) == "8f11f1406d481de44626ff778effb09b"
}

