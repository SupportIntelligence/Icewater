import "hash"

rule m3e9_4727e44180001112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4727e44180001112"
     cluster="m3e9.4727e44180001112"
     cluster_size="56 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre kryptik malicious"
     md5_hashes="['a531cdf3d52efe1914490be81f7ba4b1', 'c9a2b4a7924db3c44ebf0b9b96d2970b', 'bb001ebfc4b789dd1bca4e836c2797ec']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64512,1024) == "c5fb606aebff5d97a6aa14ec0b199377"
}

