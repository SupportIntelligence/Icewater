import "hash"

rule m3e9_4a5c4b4ceeb1d311
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4a5c4b4ceeb1d311"
     cluster="m3e9.4a5c4b4ceeb1d311"
     cluster_size="650 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="coinminer zusy maener"
     md5_hashes="['910037cf9f2da6eba0d3a60110aa60d6', 'a8fd7c1e0c918cbcd1b4b1535f3f29bf', '6dacaf7dc7cbd21bb90b81b92b6eaf03']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(42144,1028) == "94d857c7978557e268f768771ff96d4c"
}

