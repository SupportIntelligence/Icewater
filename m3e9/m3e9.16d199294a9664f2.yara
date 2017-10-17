import "hash"

rule m3e9_16d199294a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d199294a9664f2"
     cluster="m3e9.16d199294a9664f2"
     cluster_size="1483 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy shipup zbot"
     md5_hashes="['a453e778c0a6a9636c832b9307750819', 'a05d3eea1896cd2731e01690b6f2de44', '042d4d937cc9aadadb67a02b9e6ad33a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(212480,1536) == "ed8b98743f3a32a3933347ead3f37b8d"
}

