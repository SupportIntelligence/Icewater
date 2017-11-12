import "hash"

rule n3e9_0b19949dc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b19949dc6620b12"
     cluster="n3e9.0b19949dc6620b12"
     cluster_size="1291 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="dorkbot ainslot injector"
     md5_hashes="['8cc5aff0042ffcafa8ff3caee778e2ee', '05c19b6c7291c04ffad611997f52ed59', '5693c1ef70798a9222736fa27b671e9f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(444928,1024) == "2c5a0e4f2020e0ce3d599abb02d7c23b"
}

