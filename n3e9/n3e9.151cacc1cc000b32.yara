import "hash"

rule n3e9_151cacc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.151cacc1cc000b32"
     cluster="n3e9.151cacc1cc000b32"
     cluster_size="1878 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="allaple rahack networm"
     md5_hashes="['3a78b28b541693b7a99fd7fc4e1c7fd1', '0279938cf8e506739f09506853cda395', '0260169edfccc931b7815660e9963512']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(83456,1024) == "4a4080ab9387ebb9aea646c2e4b067fe"
}

