import "hash"

rule k403_139494f9c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.139494f9c9000b16"
     cluster="k403.139494f9c9000b16"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hackkms risktool riskware"
     md5_hashes="['a207d5c7df11e6ab96eca41f49265832', 'db4e01ac990a6fc67da821f211a24dfe', 'a207d5c7df11e6ab96eca41f49265832']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "1b02f02ac9669e5ee50ba580380dd5c3"
}

