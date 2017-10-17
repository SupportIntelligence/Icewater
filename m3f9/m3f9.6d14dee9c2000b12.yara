import "hash"

rule m3f9_6d14dee9c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.6d14dee9c2000b12"
     cluster="m3f9.6d14dee9c2000b12"
     cluster_size="63 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="symmi swisyn abzf"
     md5_hashes="['b44ac07f9b1b302e6cb67916bfaae3a2', 'd70c70604ea5ad5d1b97df46495814e5', '4454e679596c57f06d23f9a7d57bf61e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(8192,1024) == "9f712feaffef3b90b4425924542b4546"
}

