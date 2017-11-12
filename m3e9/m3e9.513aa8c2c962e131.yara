import "hash"

rule m3e9_513aa8c2c962e131
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.513aa8c2c962e131"
     cluster="m3e9.513aa8c2c962e131"
     cluster_size="603 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a90960ac12deb43a0e63c5e742da0da7', '4b3fab80e4f3be27f7a5bee143f6d57f', '9b635e97f79cc8f0a59fd8507b76546c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(169472,1024) == "c64f9367144db1db781024669c374a8d"
}

