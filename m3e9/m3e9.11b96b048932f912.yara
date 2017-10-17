import "hash"

rule m3e9_11b96b048932f912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.11b96b048932f912"
     cluster="m3e9.11b96b048932f912"
     cluster_size="52 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="lethic shipup gepys"
     md5_hashes="['ac84a84c60fa0f26dd1b0147bb670c83', 'c5a534cf938d381c963a28c56c8bbd43', 'c5a534cf938d381c963a28c56c8bbd43']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(1024,1024) == "863f9b2f48083834fc3522b9f5f86e83"
}

