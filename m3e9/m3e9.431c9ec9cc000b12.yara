import "hash"

rule m3e9_431c9ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.431c9ec9cc000b12"
     cluster="m3e9.431c9ec9cc000b12"
     cluster_size="112 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack virut"
     md5_hashes="['ac22c5bc5c1d6f2c66c5a14fa84d7acf', 'b1c66b31d5422d76771516502675993b', 'b0af08bfa69e9a7414d212217e9e7326']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(81408,1024) == "bbba8d45598f83db623d488a1ac2de1e"
}

