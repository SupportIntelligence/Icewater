import "hash"

rule n3e9_499825cbc6620b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.499825cbc6620b16"
     cluster="n3e9.499825cbc6620b16"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['a85c9321e4ede400ab12f9914f59b68e', 'b64052a3e5fced3865135b47da260c38', 'd381d1a54cf9e0294263fdc645b9df48']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(436736,1024) == "b7a5262ff43994734cf2fccdbf263cf3"
}

