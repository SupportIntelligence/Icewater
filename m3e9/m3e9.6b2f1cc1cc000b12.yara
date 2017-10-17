import "hash"

rule m3e9_6b2f1cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f1cc1cc000b12"
     cluster="m3e9.6b2f1cc1cc000b12"
     cluster_size="375 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="aliser small alisa"
     md5_hashes="['b115aab620089a4497bc6b8b2e88d239', 'b44543d03001a08d4bbdb10c70daa334', 'afa76ec064f0e3d49aa1ed62236f9e26']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27648,1024) == "4e761ac11d30dc1172b0b33bfd79719a"
}

