import "hash"

rule m3e7_08b9111ac2210932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.08b9111ac2210932"
     cluster="m3e7.08b9111ac2210932"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious downloadguide applicunsaf"
     md5_hashes="['6d11c96760e8cae5eed49fe99d65e20f', '6d11c96760e8cae5eed49fe99d65e20f', '4642932a18588ff44e88f81174660a10']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(110592,1024) == "81623eb81506baead676074f51904be7"
}

