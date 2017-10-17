import "hash"

rule m3e9_611e3689c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611e3689c8000b32"
     cluster="m3e9.611e3689c8000b32"
     cluster_size="286 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack starman"
     md5_hashes="['b6f5c6b69d8c89036a7fc06f94af046f', 'c516364d397789aa0f03666cb790f834', 'ba79a98f1d7d9bc5cc8067da0d367215']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62060,1051) == "6b92d4de5a9816ad40ab710f60080201"
}

