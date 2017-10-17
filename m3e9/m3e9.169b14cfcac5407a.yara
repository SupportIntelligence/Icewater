import "hash"

rule m3e9_169b14cfcac5407a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.169b14cfcac5407a"
     cluster="m3e9.169b14cfcac5407a"
     cluster_size="85 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ca61909e6a4da6fe2a3a9f2a28cc4017', '0fe8eb3c46c134fc74d9b4c1af859e7b', '9f8237492baa45ca13f16e6dbb8eba12']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(126976,1024) == "8d58ed16906ae198e8c0039b79b0e709"
}

