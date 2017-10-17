import "hash"

rule n3e9_31ca949982200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca949982200932"
     cluster="n3e9.31ca949982200932"
     cluster_size="69 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['a4a7453cf50b37f3043a843aa0a8ba2c', '3ed7d7fe6800cddc4653fb2887dc19db', 'd617bb43854ec6c22456e844f32ce912']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(433997,1033) == "8ad58842a7a9a16ab3b93793b45a27c5"
}

