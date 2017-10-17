import "hash"

rule m3e9_369db37b693a8b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.369db37b693a8b12"
     cluster="m3e9.369db37b693a8b12"
     cluster_size="208 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['bb8a01cb86fa6b7f09b663a3a2e3a17b', 'cb98c78acfabe6dbfd1832f188d32260', '63ecb64cdb3961244471426f6f300cf1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(114688,1024) == "a4d28a6820827a437986f828c97f5c6b"
}

