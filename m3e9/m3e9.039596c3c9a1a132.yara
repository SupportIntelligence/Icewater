import "hash"

rule m3e9_039596c3c9a1a132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.039596c3c9a1a132"
     cluster="m3e9.039596c3c9a1a132"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="juched zusy ganelp"
     md5_hashes="['bfbf40cf34c89806adc42e29347852e2', 'a383b6affafa61fb50d5c4f689833c14', '2067cbefafc33560ae14f55b261cf9e7']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(184320,1024) == "f7eed80c4704c220a796217f86213f11"
}

