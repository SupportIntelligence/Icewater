import "hash"

rule m3e9_692596c9cc001932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692596c9cc001932"
     cluster="m3e9.692596c9cc001932"
     cluster_size="16350 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="pyllb virut malicious"
     md5_hashes="['00a50140a8f6072abfaf56f9cdefd68e', '04cdb92230e80719b3a6f5961ed1d0be', '14d9580f2b8ec8918d4bc37cfd4cae01']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27648,1024) == "eb84d5099741b25f361240d9225ba20e"
}

