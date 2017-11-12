import "hash"

rule n3e9_2d16a98dcf0f4b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2d16a98dcf0f4b12"
     cluster="n3e9.2d16a98dcf0f4b12"
     cluster_size="1180 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy malicious adsearch"
     md5_hashes="['35f17ced63ee98cc888a26c7b1e76dc0', '0086c5fa7654816aa744d4566ce8490d', '0cb162edc72cba2138aff2bc16704cd7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(685542,1026) == "085ffd6b2a22232c3340221a5bac6e71"
}

