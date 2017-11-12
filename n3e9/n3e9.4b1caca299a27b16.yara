import "hash"

rule n3e9_4b1caca299a27b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b1caca299a27b16"
     cluster="n3e9.4b1caca299a27b16"
     cluster_size="412 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c3e69052fcb38307112057d844fdf684', '40afeab9f96e1ae402ec0a85f1a97b28', '9f59fb5561f8a092b87855770514ad51']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(755712,1024) == "a84c9132a6889fcb552bdd8b16ca615f"
}

