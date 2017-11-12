import "hash"

rule n3e9_599dbf89c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.599dbf89c8000932"
     cluster="n3e9.599dbf89c8000932"
     cluster_size="31663 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="elzob zusy shiz"
     md5_hashes="['085444b45df92f3c5a29313462f043d4', '066b35c5a31754bb71ad9ffc17d8cbfb', '031295668b8293dc91e1e9b7648d8ad7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(14104,1024) == "113b12abbc212dae31c2a6c7b4076c19"
}

