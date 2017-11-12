import "hash"

rule k3e9_6b64d34b8acb4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b8acb4912"
     cluster="k3e9.6b64d34b8acb4912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['19c696965f01d604ffe4c6e92a8e3294', 'c81d9fd9b1dec5df4d2ebf4b98ba8b6b', '19c696965f01d604ffe4c6e92a8e3294']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(24828,1036) == "b430fb8cdfb0eaa02d3e9c2620da748a"
}

