import "hash"

rule k3e9_539afac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.539afac1c4000b12"
     cluster="k3e9.539afac1c4000b12"
     cluster_size="27238 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mydoom email malicious"
     md5_hashes="['06f2e4935a5c41e3fe657e769f459be5', '0142ecb02b506c201a14b6d0c7e6399b', '06fd8514b5e2404dcc6dfdc16fd83841']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18944,1024) == "761dfca1f1eee46aa28db54312173457"
}

