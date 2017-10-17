import "hash"

rule n3e9_29c615e4ea208b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c615e4ea208b12"
     cluster="n3e9.29c615e4ea208b12"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="crypt trojandropper cuegoe"
     md5_hashes="['0855a2095eee821bbaac9a32dcb21b27', '0855a2095eee821bbaac9a32dcb21b27', '6a0408ebb1f4731b1e174f9bff5467eb']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(532460,1028) == "00fc4f62daf0da374568acfeb55d7e7f"
}

