import "hash"

rule m3f0_495add0a9deb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.495add0a9deb1912"
     cluster="m3f0.495add0a9deb1912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy locky ransom"
     md5_hashes="['88752a9039fcba1baab163ef012b8327', '2a1d42995a47d80b8632e25eb94e2ba9', '2a1d42995a47d80b8632e25eb94e2ba9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(166912,1024) == "fae77c7202f7947434fb3a5df9b9adbe"
}

