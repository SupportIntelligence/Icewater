import "hash"

rule n3e9_29c641e4ea208b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c641e4ea208b12"
     cluster="n3e9.29c641e4ea208b12"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="crypt trojandropper cuegoe"
     md5_hashes="['bf11aaf5b437bd8c47e75f6f834fa096', '3cd9e5a2d425ae9f0fe137e77b0ce353', 'bf11aaf5b437bd8c47e75f6f834fa096']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(532460,1028) == "00fc4f62daf0da374568acfeb55d7e7f"
}

