import "hash"

rule m3e9_169b14cfcac5406a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.169b14cfcac5406a"
     cluster="m3e9.169b14cfcac5406a"
     cluster_size="73 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['463d4dba70ba46ee8a0df4fc2e38e5f1', '3e0173f11c01ead009c29b5b1d70304e', '463d4dba70ba46ee8a0df4fc2e38e5f1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(126976,1024) == "8d58ed16906ae198e8c0039b79b0e709"
}

