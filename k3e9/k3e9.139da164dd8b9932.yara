import "hash"

rule k3e9_139da164dd8b9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164dd8b9932"
     cluster="k3e9.139da164dd8b9932"
     cluster_size="679 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a37e5f93b150d208250c11f927073594', '06255315950e537cff4e8140aa4a9ca6', '9e1feb135deecb58d4cc0ec564705aca']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,1024) == "de88ae07cff08473a9c10f1d9aaff856"
}

