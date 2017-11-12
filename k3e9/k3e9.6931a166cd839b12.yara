import "hash"

rule k3e9_6931a166cd839b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6931a166cd839b12"
     cluster="k3e9.6931a166cd839b12"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['af9057262c781d6e0a6317a6c4722dd2', '289b60acc27d25f21cd01268baad96cd', '289b60acc27d25f21cd01268baad96cd']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(15360,1024) == "f751fc03ac106c581a7746569740097e"
}

