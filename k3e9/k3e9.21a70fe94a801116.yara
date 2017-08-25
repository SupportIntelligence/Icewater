import "hash"

rule k3e9_21a70fe94a801116
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.21a70fe94a801116"
     cluster="k3e9.21a70fe94a801116"
     cluster_size="33924 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="generickd androm backdoor"
     md5_hashes="['01c3bf8e3f535d0a3384b4b92bef0f0f', '02505edf0e6dd4716ecfdf17a437b059', '00fe68a3adbb9b2ef791ede99a6ceef8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9728,1024) == "4ab982450c4169cb439580b13a70fedd"
}

