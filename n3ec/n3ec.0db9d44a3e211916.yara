import "hash"

rule n3ec_0db9d44a3e211916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.0db9d44a3e211916"
     cluster="n3ec.0db9d44a3e211916"
     cluster_size="58 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious attribute kryptik"
     md5_hashes="['39759b913637abe4f9a97e4e593639ad', 'b21924ea402ac429415977f83bf15824', '39759b913637abe4f9a97e4e593639ad']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(266752,1024) == "b0920ba8886c467069af126ad81b4b67"
}

