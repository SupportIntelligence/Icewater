import "hash"

rule m3e9_2814d2d9e616d912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2814d2d9e616d912"
     cluster="m3e9.2814d2d9e616d912"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['112b19e30434841f12b666b458800821', '4ab152b48a42a8e7ee03b101852c3547', '4ab152b48a42a8e7ee03b101852c3547']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(129536,1024) == "90b33ac36218b8f2a29170731938ae26"
}

