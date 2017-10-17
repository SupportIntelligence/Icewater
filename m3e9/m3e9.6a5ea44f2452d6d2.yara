import "hash"

rule m3e9_6a5ea44f2452d6d2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6a5ea44f2452d6d2"
     cluster="m3e9.6a5ea44f2452d6d2"
     cluster_size="408 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a529bf3f2b45d74aced7070aae110e15', '1fe32316843a35cb9164b6a8cd7337f5', 'b3063c4b8395cc9fd451b7325b83f01c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(138240,1127) == "fddcc1b26534ac99f2294c97171db142"
}

