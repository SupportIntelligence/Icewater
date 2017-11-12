import "hash"

rule k3e9_6b225ec144000b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b225ec144000b10"
     cluster="k3e9.6b225ec144000b10"
     cluster_size="48323 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="generickd upatre selfdel"
     md5_hashes="['074ff7146637bd5a39f768c4c3320882', '01f1f0c5367fb051e4df85a1a894809b', '074ff7146637bd5a39f768c4c3320882']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "9c142f385436c5fcfa043a13f366fc77"
}

