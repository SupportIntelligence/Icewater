import "hash"

rule n3ed_0ce3390f3a136b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ce3390f3a136b16"
     cluster="n3ed.0ce3390f3a136b16"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b195ed39677b2b690f36c0f833522222', '1102ded41be97fcdc7e598d7835b5f25', 'd3a81de14d6c2047060f8f13d0088d99']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(635392,1024) == "23ef210ac6a5becc04bd46daffa5e04f"
}

