import "hash"

rule k3e9_073cae19c29a9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.073cae19c29a9932"
     cluster="k3e9.073cae19c29a9932"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="berbew backdoor qukart"
     md5_hashes="['d66c096ea13b7b727e2fbdd69b11815e', 'c1406a24289d005e926d669cda2a1b4c', '95544c26f3a7a5f860e6b426f6811d83']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

