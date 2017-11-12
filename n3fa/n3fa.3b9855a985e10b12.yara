import "hash"

rule n3fa_3b9855a985e10b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fa.3b9855a985e10b12"
     cluster="n3fa.3b9855a985e10b12"
     cluster_size="16304 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="adsnare malicious cloud"
     md5_hashes="['05c29cc4a485bb74bcec0bcdd28daa05', '026b271a0c15c402d7702cbdafe6bcbc', '03f197a500792b3a8bd0c7cf9b745ca4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(654848,1024) == "9833a6d9547b34bbbad0d2ec26e689a5"
}

