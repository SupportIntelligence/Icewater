import "hash"

rule o3e9_3b1108968c0a711e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.3b1108968c0a711e"
     cluster="o3e9.3b1108968c0a711e"
     cluster_size="1360 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonstr installmonster malicious"
     md5_hashes="['0e716b359a95eb10c3ce8c8890a500ac', '23592a21b8b9f63345a7827c6d169d37', '0e798082d15b1b2584d94307abb9879d']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2833115,1025) == "a11d5834089b17ad533e0bbf6414c969"
}

