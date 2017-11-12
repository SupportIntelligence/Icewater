import "hash"

rule j3ec_59d910e9c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.59d910e9c0000b12"
     cluster="j3ec.59d910e9c0000b12"
     cluster_size="519 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="fileinfector ldjci malicious"
     md5_hashes="['e8291be0470023e935be387c7d65a9c2', 'c3ffcaf9404a28400117135129065ba9', '1637be5e83f8f992cda5675ee6ac2a0e']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(8192,1280) == "6982cd0208646b15dcc8431fdf1c13e7"
}

