import "hash"

rule m3e7_211e3ac1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.211e3ac1cc000b12"
     cluster="m3e7.211e3ac1cc000b12"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack starman"
     md5_hashes="['b8d3595f2163f72d1c81126ff5f11af4', 'a1e7b2d3fbcd412668a2f20b1906daa1', 'ac39ef68d298660c89c1aa65f9c51c0c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57856,1024) == "742ba6f624d3eb91518ce0694aaadc00"
}

