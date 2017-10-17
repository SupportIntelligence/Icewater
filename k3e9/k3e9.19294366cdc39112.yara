import "hash"

rule k3e9_19294366cdc39112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.19294366cdc39112"
     cluster="k3e9.19294366cdc39112"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['c751935db7dc2400a982f82c9badc57b', 'c6f2c44313fede23fe370f3115f4f02d', 'c6f2c44313fede23fe370f3115f4f02d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "0449c30b832c1c60111f03ffa49ccd7d"
}

