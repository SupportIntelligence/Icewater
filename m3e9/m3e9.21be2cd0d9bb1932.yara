import "hash"

rule m3e9_21be2cd0d9bb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.21be2cd0d9bb1932"
     cluster="m3e9.21be2cd0d9bb1932"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="graftor delf backdoor"
     md5_hashes="['ea25881726fcca1b5c786f0081f2912f', 'd7be13c8e4a4cdcd558c2c70bd02b2f8', 'ea25881726fcca1b5c786f0081f2912f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(130440,1027) == "1e0c5a10ac9d716dff84d700d014df8b"
}

