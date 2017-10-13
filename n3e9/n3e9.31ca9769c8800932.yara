import "hash"

rule n3e9_31ca9769c8800932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca9769c8800932"
     cluster="n3e9.31ca9769c8800932"
     cluster_size="703 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy orbus malicious"
     md5_hashes="['036185152698ccb516030fd46d25954c', 'ad05f828757644a49a1352df9b928056', 'b46962e871cb9669a30fa3b5957c5a73']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(5136,1028) == "1e234acf0ceca011affdfbe810ca8553"
}

