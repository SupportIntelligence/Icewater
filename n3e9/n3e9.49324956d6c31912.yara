import "hash"

rule n3e9_49324956d6c31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49324956d6c31912"
     cluster="n3e9.49324956d6c31912"
     cluster_size="52 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="jacard malicious yantai"
     md5_hashes="['26757789fc3c5243ae16b138f5c3ce15', '19323353732c40ca3ef44e580a6a3c78', 'fbf2a492125ec23d01c37267ccfe685d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(599402,1039) == "66d1c4f89625471ca39d97192d582de5"
}

