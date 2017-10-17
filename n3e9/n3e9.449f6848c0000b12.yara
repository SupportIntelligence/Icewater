import "hash"

rule n3e9_449f6848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.449f6848c0000b12"
     cluster="n3e9.449f6848c0000b12"
     cluster_size="56 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus wbna sirefef"
     md5_hashes="['a2b15d7339f8fc53595e59f8eab85c97', 'b84ae584c13a81b78fa20ec593f01471', '87461a121abc27b895ee0aefe1cda13e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(219136,1024) == "1d791db45ac35570a201c78e876b0594"
}

