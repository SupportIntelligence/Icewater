import "hash"

rule n3ed_4aa73a41c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.4aa73a41c8000932"
     cluster="n3ed.4aa73a41c8000932"
     cluster_size="197 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="dangerousobject heuristic malicious"
     md5_hashes="['fb8072869400f4c4465c395f551a0d50', '144885feeaae98d4d899155e8f4383e1', '573d6ee0f762e927374d6669d93c10b4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(305496,1066) == "1a3e5d1c9cbd0cc09b72eb48971e6280"
}

