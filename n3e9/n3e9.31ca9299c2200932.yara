import "hash"

rule n3e9_31ca9299c2200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca9299c2200932"
     cluster="n3e9.31ca9299c2200932"
     cluster_size="94 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy orbus siggen"
     md5_hashes="['947068f7874f19159bc71880c4159b55', 'd1677d147a5524636ba10349bd38409b', 'bbc023ceb1e11a9c3407dca9b82ef2e1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(433152,1024) == "82a703004df5fdddd1924205610d269c"
}

