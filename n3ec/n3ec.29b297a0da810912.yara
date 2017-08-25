import "hash"

rule n3ec_29b297a0da810912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.29b297a0da810912"
     cluster="n3ec.29b297a0da810912"
     cluster_size="6 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="strictor malicious startsurf"
     md5_hashes="['3eb99203d32a754f4c265e030cfc6244', '969af67881491989a8673388de9843cf', 'b2a5987fe74f66fe63c31aedeafce0b1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(614400,1024) == "1f61e40016cadcc04a35b35dd3b3eb71"
}

