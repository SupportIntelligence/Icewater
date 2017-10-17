import "hash"

rule k3e9_05355856dbbb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05355856dbbb1932"
     cluster="k3e9.05355856dbbb1932"
     cluster_size="44 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c76014e98f083cf3bba4cd12727b7779', 'c17aa1c2c525fa193337501e08bb5f29', 'c17aa1c2c525fa193337501e08bb5f29']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17408,1024) == "0fe9e98508ccf8e184d819bf21b5ad2b"
}

