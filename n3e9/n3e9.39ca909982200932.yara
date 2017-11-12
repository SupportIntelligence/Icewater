import "hash"

rule n3e9_39ca909982200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39ca909982200932"
     cluster="n3e9.39ca909982200932"
     cluster_size="120 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['765643cfd84e42b4052737bb41eba183', 'ac34f81241111f74d5989dfc59201842', '86c03ca3e5e64594d5d4a87be7d0b8ec']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(437589,1033) == "19513ae4720d68d46961f2dbda6f47a6"
}

