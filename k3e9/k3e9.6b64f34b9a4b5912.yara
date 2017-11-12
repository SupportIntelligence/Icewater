import "hash"

rule k3e9_6b64f34b9a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64f34b9a4b5912"
     cluster="k3e9.6b64f34b9a4b5912"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['3f9ba507c9ffce1e1ad12a3c27a5f012', 'd42678e0e4c63b3ed17cb3d945aa7911', 'b73e58cfdbf13b446b14bfa477a48de4']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(24828,1036) == "b430fb8cdfb0eaa02d3e9c2620da748a"
}

