import "hash"

rule m3ed_119bea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.119bea48c0000b32"
     cluster="m3ed.119bea48c0000b32"
     cluster_size="136 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     md5_hashes="['8c849a0298e216d1aa1be1dc603542e2', '613f8930a1c79f5299f49e69380a7394', '9a07f117aeb472cdd40f4af2dd319f2f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(65536,1195) == "89c7d90c47e5d82968c721a432451dda"
}

