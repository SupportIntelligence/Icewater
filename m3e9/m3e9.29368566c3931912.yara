import "hash"

rule m3e9_29368566c3931912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29368566c3931912"
     cluster="m3e9.29368566c3931912"
     cluster_size="344 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="symmi injector tinba"
     md5_hashes="['ab5631911806bbc7a45eff9acf15c537', '4ac5a46ccedacb06b9ed9a6076cf1bf2', 'a7a38fc0a65ef8f41dc88a4eaeb5750b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(141824,1536) == "371d47070a53b14ceaa6b365e75da3ac"
}

