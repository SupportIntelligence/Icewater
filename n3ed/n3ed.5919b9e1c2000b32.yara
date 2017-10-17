import "hash"

rule n3ed_5919b9e1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5919b9e1c2000b32"
     cluster="n3ed.5919b9e1c2000b32"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['bf8a82e3a1ca4bb6187af56aa350239e', '9d4adcacea7e951cbec32ce9bef2aa6b', 'bf8a82e3a1ca4bb6187af56aa350239e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(91136,1098) == "6328c395671af3d442197f887ae83fcf"
}

