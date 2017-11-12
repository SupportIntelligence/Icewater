import "hash"

rule m3e9_611e3ac1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611e3ac1cc000b16"
     cluster="m3e9.611e3ac1cc000b16"
     cluster_size="494 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171018"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['2b35a4544e6ee55cf6c7dbdae72716c9', 'a5e29da8148308a0d200cac2dc427ce8', '2bcec843d85ea32c1a13115df0e1c018']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(62976,1024) == "38345c2f0e0fb848e12408e6736482bc"
}

