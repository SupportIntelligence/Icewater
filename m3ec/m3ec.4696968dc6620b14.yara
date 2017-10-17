import "hash"

rule m3ec_4696968dc6620b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.4696968dc6620b14"
     cluster="m3ec.4696968dc6620b14"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sality malicious sector"
     md5_hashes="['a6452e142019cd87ad2e4d835359c2f9', '021081d164d1c4ffc248c756833620a8', 'a6452e142019cd87ad2e4d835359c2f9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(26744,1064) == "929c1e020860555fe55b99da1bc9c6e9"
}

