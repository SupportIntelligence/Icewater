import "hash"

rule j3f4_14a85eb91ac31130
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.14a85eb91ac31130"
     cluster="j3f4.14a85eb91ac31130"
     cluster_size="295 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy onlinegames genericrxbn"
     md5_hashes="['142076d9d833b569ae543b71af99e7aa', 'fdb828e9431e2908b3b3b48e927aeaec', '155c308b96269ed185b09df4c2bf7861']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(8192,1536) == "adf508ff128841c209c548c7e7bcd058"
}

