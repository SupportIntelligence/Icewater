import "hash"

rule n3ed_0ce3390f3a1342d2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ce3390f3a1342d2"
     cluster="n3ed.0ce3390f3a1342d2"
     cluster_size="68 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b0bae2bfe021b0688ef5e0f50c53b119', 'bf44355c5c1ed64850f542bd65fbbcac', 'b80aca72978555440439a15045546a8f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(573952,1024) == "5ecc66daf37afcd45ee35aa85806cf8c"
}

