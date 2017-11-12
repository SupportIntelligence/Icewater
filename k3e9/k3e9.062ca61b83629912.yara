import "hash"

rule k3e9_062ca61b83629912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.062ca61b83629912"
     cluster="k3e9.062ca61b83629912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qukart berbew backdoor"
     md5_hashes="['4e1f7cdaea9e2e3a783378f6395bf40f', 'aadf80034ed3be06e9b7918f81765c1d', 'a8e1f6b2067bc954d5689a0a87e48d24']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

