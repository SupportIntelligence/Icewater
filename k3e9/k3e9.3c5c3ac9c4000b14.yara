import "hash"

rule k3e9_3c5c3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c5c3ac9c4000b14"
     cluster="k3e9.3c5c3ac9c4000b14"
     cluster_size="92 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['acf552bc3124cacb31e789e062f00c3f', 'ec8a19ab0f578b6b207f0121a7b3ee29', 'd866bc70244af929432757df32f03a7b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

