import "hash"

rule k3e9_262ca61b93bb9912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.262ca61b93bb9912"
     cluster="k3e9.262ca61b93bb9912"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="berbew qukart backdoor"
     md5_hashes="['9b30846498b8b412bcb7a2ca65126fc1', 'cb77929e0eec5a7888da1b10d40c65bf', 'c4a38a76b1c1d6723754f5eede332a24']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

