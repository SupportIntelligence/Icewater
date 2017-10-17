import "hash"

rule n3e9_31ca929982200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca929982200932"
     cluster="n3e9.31ca929982200932"
     cluster_size="45 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['bf0fbc00332b483fbff60d91137d4710', 'c68f047db69334b42a7f38e8f4cddfa4', 'dd0221409d38853b2c746e5bbb7c2413']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(433997,1033) == "8ad58842a7a9a16ab3b93793b45a27c5"
}

