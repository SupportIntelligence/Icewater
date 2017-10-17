import "hash"

rule m3ed_4b958d1f449646d2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4b958d1f449646d2"
     cluster="m3ed.4b958d1f449646d2"
     cluster_size="359 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['d78231a12f8b9139f5913f04daa824d7', '15ad4a96f99c71915b0f2dce70a24eb5', '2365675e2f34c2bfe2eb97c81b1fd5fa']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(156672,1536) == "0f4c07f5fc878e2aa1805fefc0c25f7a"
}

