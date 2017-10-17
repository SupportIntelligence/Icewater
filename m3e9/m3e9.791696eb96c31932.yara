import "hash"

rule m3e9_791696eb96c31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.791696eb96c31932"
     cluster="m3e9.791696eb96c31932"
     cluster_size="59 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['661da926aee9dece10f26699eae58375', '3036519d906a716cea5cd35900dffb46', 'cf1d3fbb27448fac16d2c36b65731cae']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(125782,1194) == "de7cddf34a14a2a8f138dbc5845da8ba"
}

