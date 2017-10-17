import "hash"

rule m3ed_52ba5b2a27045646
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.52ba5b2a27045646"
     cluster="m3ed.52ba5b2a27045646"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['8163dfdfb3d6cf9e0f57c0abeff99b83', '804d37b83b242d04d8b19bb655f2b52f', '8163dfdfb3d6cf9e0f57c0abeff99b83']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1127) == "974fce2e259d417be646081135899951"
}

