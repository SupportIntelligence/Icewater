import "hash"

rule k3e9_05355856dabb0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05355856dabb0932"
     cluster="k3e9.05355856dabb0932"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['3ab8da7de6f41a283f8347658a4abd95', '0c607a5a8635f951b9376154a80fb8e2', 'ddf2a4fa7e1fbc5dece03c881687815c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17408,1024) == "0fe9e98508ccf8e184d819bf21b5ad2b"
}

