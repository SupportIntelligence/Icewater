import "hash"

rule n3e9_116601a7ca231512
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.116601a7ca231512"
     cluster="n3e9.116601a7ca231512"
     cluster_size="925 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['0390fb511bfbbc9ffd8d2981c7bef34e', '00910cbb3ef3069522e45c913fb078f1', '14d8fc3e01d3e00b8d6d8352de50fba5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(151040,1024) == "c10ec287aa138bf9e5e808f691c477ec"
}

