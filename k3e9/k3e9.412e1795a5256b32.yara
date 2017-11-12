import "hash"

rule k3e9_412e1795a5256b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.412e1795a5256b32"
     cluster="k3e9.412e1795a5256b32"
     cluster_size="56 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['dd13ad4ece828ab302d2b120d162b778', 'dd558b14d89a688ccc1857cec1dbf819', 'c01931b4cda65ad704422a00311685ac']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29526,1109) == "8a276caafdbf30bba5d7fac2a3e0c83d"
}

