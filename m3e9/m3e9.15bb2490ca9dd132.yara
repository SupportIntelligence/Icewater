import "hash"

rule m3e9_15bb2490ca9dd132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.15bb2490ca9dd132"
     cluster="m3e9.15bb2490ca9dd132"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ransom hpcerber malicious"
     md5_hashes="['145b410a17afe8cb154d64f7d5bf844f', 'e6edb94498a62b8772b275642f613428', '1496f453035c4a844741e8665df2a236']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(194888,1070) == "1ed980a4869a59224a4b66116fcf242f"
}

