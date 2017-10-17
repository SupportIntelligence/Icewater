import "hash"

rule m3ed_4b958d1f44964cf2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4b958d1f44964cf2"
     cluster="m3ed.4b958d1f44964cf2"
     cluster_size="187 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['e35fb6b0e705ca4e821832e1f0026a61', 'e18386a96a0cf0932cf28953637db800', 'b808207cbca4354a917c86a47a66bf85']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(156672,1536) == "0f4c07f5fc878e2aa1805fefc0c25f7a"
}

