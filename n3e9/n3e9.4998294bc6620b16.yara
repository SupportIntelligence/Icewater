import "hash"

rule n3e9_4998294bc6620b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4998294bc6620b16"
     cluster="n3e9.4998294bc6620b16"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['c7b869fed1e10eb8c6daa9989287d266', 'a83092ed86931c8fd77112c3889e66a0', 'a83092ed86931c8fd77112c3889e66a0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(108544,1024) == "9650727afb29740793894269db598dc4"
}

