import "hash"

rule n3ed_39857a1eba231932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39857a1eba231932"
     cluster="n3ed.39857a1eba231932"
     cluster_size="27 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['87a780f82655ee23d9d8e45c3233ced9', 'b6f5ea78a1a647110980dcd6910cd6ee', '7e38e5c74e94d399e06d1666d8e2b6e9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(371712,1024) == "18dbd5f35c723e3b2d0cc3baafc60c36"
}

