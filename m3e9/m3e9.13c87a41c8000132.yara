import "hash"

rule m3e9_13c87a41c8000132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13c87a41c8000132"
     cluster="m3e9.13c87a41c8000132"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre ipatre kryptik"
     md5_hashes="['3dd05e8676d29a0d66ead16a35eb57f1', '5304f55ecbcdc98ecea9ee93407ea53c', 'a27a074a5011574d21b9395bf5a15ef7']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64512,1024) == "84b997d3e84c3d1b56c245af95eb4c3b"
}

