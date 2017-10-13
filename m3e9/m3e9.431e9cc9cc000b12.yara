import "hash"

rule m3e9_431e9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.431e9cc9cc000b12"
     cluster="m3e9.431e9cc9cc000b12"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['d32e55f34d245337cb63a8b5fd1d673c', 'a3a8ee3ebe8f8c50b02708ee34a9454b', 'd8e0b5c46172a398a2b63624119bff49']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62976,1024) == "38345c2f0e0fb848e12408e6736482bc"
}

