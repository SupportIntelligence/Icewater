import "hash"

rule m3e9_631e97a9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631e97a9ca000b32"
     cluster="m3e9.631e97a9ca000b32"
     cluster_size="62 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack starman"
     md5_hashes="['a4fc9e6191b38dc53fe1bfcdc0bab3be', 'bac0d60ce9a085e049662b9a9b0abfa9', 'b2a30f7132f84d54d4aec236eadcb697']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73291,1029) == "da5ab260d3f3b2aa7508f7dfc1ddb857"
}

