import "hash"

rule k3f4_0c3249c2d1a34852
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.0c3249c2d1a34852"
     cluster="k3f4.0c3249c2d1a34852"
     cluster_size="397 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="browsefox msilperseus yontoo"
     md5_hashes="['0160b32dc2a86a3cd42c9f1e331441b2', '50523b4bd6539c1c5b04764565d314de', '1a61aaf07971ffb95be5398a8208627d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(57344,1536) == "691afa3c7ed4daf6e7433dd1ef89157c"
}

