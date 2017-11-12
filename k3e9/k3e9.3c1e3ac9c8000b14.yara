import "hash"

rule k3e9_3c1e3ac9c8000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1e3ac9c8000b14"
     cluster="k3e9.3c1e3ac9c8000b14"
     cluster_size="94 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor razy simbot"
     md5_hashes="['672db740b00ba65a1aaad37b38017817', 'f890c181b57320ff8b0c0e97ecfa6ec1', '8dac8c81f01f27e60834b778eae43f9c']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

