import "hash"

rule n3ec_61466a48c0000b30
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.61466a48c0000b30"
     cluster="n3ec.61466a48c0000b30"
     cluster_size="291 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c3fa45cccafad25939c0315d23be0fe7', 'c3fa45cccafad25939c0315d23be0fe7', 'da2685967a4f7cc6ad8474df8aa130ec']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(244736,1024) == "94846d51b8378ad7638eff78ca70291c"
}

