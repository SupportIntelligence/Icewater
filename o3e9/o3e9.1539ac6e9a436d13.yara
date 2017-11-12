import "hash"

rule o3e9_1539ac6e9a436d13
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1539ac6e9a436d13"
     cluster="o3e9.1539ac6e9a436d13"
     cluster_size="1816 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonstr installmonster malicious"
     md5_hashes="['0f36e7acbb4281572bba4308eeb58c11', '11968c92d490a3ec42cb4c9dca3a91fd', '1bd24fc47df6c3a267238006d99131c3']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1844736,1024) == "b1ac007303f77b2ddd946181deba8128"
}

