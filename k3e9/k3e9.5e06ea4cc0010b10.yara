import "hash"

rule k3e9_5e06ea4cc0010b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5e06ea4cc0010b10"
     cluster="k3e9.5e06ea4cc0010b10"
     cluster_size="267 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre generickd waski"
     md5_hashes="['c214d8f713581e14b67b068bd5a32bda', 'ae56924aef2edb5bb8e4f2df74425d82', 'd7129631f560fd8e906c8342c7fb91ae']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "836f8256277baaf527ccdb6e1ad05384"
}

