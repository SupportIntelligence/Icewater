import "hash"

rule m3e9_5154ec869a986d16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5154ec869a986d16"
     cluster="m3e9.5154ec869a986d16"
     cluster_size="77 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['53d63377e6c2b8f124c33008f6436ba5', 'c0f3e5b2441b467b512d30cf2de624d2', 'bb786d1a6a6a1e8897ddabe9d18f5e2c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(182824,1064) == "9cf8ecfb1f9441dd702ff5d21ebd9bd9"
}

