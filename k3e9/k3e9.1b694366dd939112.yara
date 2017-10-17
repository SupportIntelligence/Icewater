import "hash"

rule k3e9_1b694366dd939112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b694366dd939112"
     cluster="k3e9.1b694366dd939112"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['42980acd23c3b919e07a55de1b66170e', '2fe64b3d242aa8292e2b1e179b481f59', '2fe64b3d242aa8292e2b1e179b481f59']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "0449c30b832c1c60111f03ffa49ccd7d"
}

