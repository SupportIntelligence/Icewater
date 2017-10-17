import "hash"

rule j3e7_61166826ca210b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.61166826ca210b32"
     cluster="j3e7.61166826ca210b32"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious corrupt corruptfile"
     md5_hashes="['8c0fa696cdb100f5cc933619bf0ad5e2', '63b9cc6481a56ce5f3b74345a4ec2150', '59fa7f7dd00c989d6b94917fede9b8a1']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "7e2a4568671b13bc8f9443cb98e18f90"
}

