import "hash"

rule n3e9_39366c8aae211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39366c8aae211932"
     cluster="n3e9.39366c8aae211932"
     cluster_size="1982 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['215b68be1414014572fdfe5fe1496710', '18d1292ac412d33b96c7e159bc96663f', '0fa9901b81e9c88fa909fe35b0f8a4c9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(61440,1024) == "821913283c3a548032a8ee12e97d41d2"
}

