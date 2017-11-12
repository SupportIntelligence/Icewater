import "hash"

rule k3e9_262ca69bd29ad111
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.262ca69bd29ad111"
     cluster="k3e9.262ca69bd29ad111"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qukart berbew backdoor"
     md5_hashes="['98569d8435bbec11525681954db8269e', 'a0d40650e051839cf2b5e0a0899645e0', 'a0d40650e051839cf2b5e0a0899645e0']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(49603,1249) == "d06857e133fd37b7cc5535176ea36368"
}

